# PQ-Shield: Design & Implementation Reference

This document is the implementation-facing companion to the Review 1
proposal (`docs/PQ_Shield_Review1.pdf`, not tracked in this repo). It
describes what was actually built, where it diverges from the original
proposal, and why.

## 1. Problem statement

Every production AI inference API is currently secured with classical
public-key cryptography (RSA / ECDSA), both broken in polynomial time by
Shor's algorithm on a cryptographically relevant quantum computer (CRQC).
The **harvest-now-decrypt-later (HNDL)** threat model means adversaries can
record encrypted traffic today and decrypt it retroactively once such
hardware exists. NIST finalized ML-KEM (FIPS 203) and ML-DSA (FIPS 204) in
August 2024, but almost no empirical work measures what migrating a
*latency-sensitive AI inference workload specifically* to these algorithms
actually costs, in concrete milliseconds, bytes, and error rates under
concurrency. PQ-Shield is an empirical measurement framework that answers
that question directly, rather than a new cryptographic algorithm.

## 2. Three configurations

| | Key establishment | Response signature |
|---|---|---|
| Control | none | none |
| A — Classical | RSA-2048-OAEP key transport | ECDSA P-256 |
| B — Hybrid | ML-KEM-768 encapsulation | ECDSA P-256 |
| C — Full PQC | ML-KEM-768 encapsulation | ML-DSA-65 |

All three protected configurations use the same symmetric layer —
AES-256-GCM, keyed by HKDF-SHA256 over the raw shared secret — so the only
independent variable across configurations is the asymmetric
key-establishment and signature primitive. This isolation is deliberate:
it is what lets Figure 2 (overhead decomposition) attribute latency
specifically to "RSA vs. ML-KEM" and "ECDSA vs. ML-DSA" rather than to
incidental implementation differences in the symmetric layer.

## 3. Protocol

```
Client                                   Server
  |--- GET /secure/handshake ------------->|   generates a FRESH ephemeral
  |<-- {handshake_id, kex_pub, sig_pub} ---|   key pair set per call
  |
  |  establish(): RSA-OAEP-encrypt a       |
  |  random 32B secret (classical) OR      |
  |  ML-KEM-768 encaps (hybrid/full-pqc)   |
  |  -> session_key = HKDF(shared_secret)  |
  |
  |--- POST /secure/predict -------------->|   accept(): decrypt/decapsulate
  |    {handshake_id, kex_blob,            |   -> recover session_key
  |     nonce, ciphertext}                 |   AES-GCM-decrypt request
  |                                        |   run model inference
  |                                        |   AES-GCM-encrypt response
  |                                        |   sign(nonce || ciphertext)
  |<-- {nonce, ciphertext, signature, ------|
  |     server_timing_ms, debug?}          |
  |
  |  AES-GCM-decrypt response              |
  |  verify(signature)                     |
```

A **fresh handshake per transaction** is the default benchmarking mode
(`bench/runner.py` without `--reuse-handshake`). This is the conservative,
worst-case measurement: production deployments that keep a connection warm
across many requests would amortize the handshake cost, and
`--reuse-handshake` exists specifically to measure that amortized case as a
secondary result.

`server_timing_ms` is always returned (needed for every RTT/handshake
benchmark row); the byte-size breakdown consumed by the HNDL script is
gated behind `X-Debug-Metrics: true` so a default response stays
production-shaped.

## 4. Divergences from the original Review 1 proposal

The Review 1 slide deck and the initial design draft described a plan
using the `liboqs-python` package directly and `mitmproxy` for the active
MITM threat scenario, with a stated goal of "no system-wide installation
required." The implementation instead:

- **Binds liboqs directly via ctypes** (`crypto/oqs_adapter.py`) against a
  locally built, minimal liboqs restricted to exactly `ML-KEM-768` and
  `ML-DSA-65` (`scripts/install_oqs.sh`), rather than depending on the
  `liboqs-python` package. This keeps the build small (under a minute, one
  core) and auditable — the ctypes bindings call four named C functions
  with hard-coded, header-verified byte lengths, rather than parsing the
  generic `OQS_KEM`/`OQS_SIG` structs (which embed function pointers and
  are sensitive to compiler struct padding).
- **Implements the MITM proxy as a small `aiohttp`-based forward proxy**
  (`threats/mitm_harness.py`) instead of a `mitmproxy` addon. `mitmproxy`
  pulls in a much larger dependency tree for functionality (TLS
  interception, a TUI, HAR export) this project does not need — all that
  is needed is "flip a byte in one JSON field of one response type,"
  which a ~40-line proxy handler does directly.
- **Adds AES-256-GCM as an explicit symmetric layer** between the
  asymmetric key-establishment and the JSON payload. The original design
  sketch signed and returned plaintext JSON directly; the implemented
  protocol treats confidentiality (AES-GCM) and integrity/authenticity
  (ECDSA/ML-DSA signature over the AEAD envelope) as separate, composable
  guarantees, which is what makes Threat Scenario 2's `--tamper-target`
  distinction (ciphertext vs. signature) a meaningful experiment rather
  than a single trivially-coupled failure mode.

## 5. Hypotheses

| # | Hypothesis | Research question |
|---|---|---|
| H1 | Full PQC adds bounded latency overhead vs. classical at low concurrency, growing sub-linearly as concurrency rises to 1,000 | RQ1 |
| H2 | Hybrid captures most of Full PQC's HNDL-relevant security benefit at less than half the added latency, because ECDSA stays cheap | RQ2 |
| H3 | ML-KEM ciphertexts are larger in raw bytes than RSA-2048 ciphertexts, but the *decryptability* of harvested ML-KEM traffic under a future CRQC is categorically different (zero, vs. RSA's eventual full exposure) — raw bytes and expected-decryptable-value are different metrics that should both be reported | RQ3 |
| H4 | ML-DSA-65 verification is not slower than ECDSA verification in wall-clock terms, despite much larger signatures, because lattice verification is comparatively cheap arithmetic | RQ4 |

H3 and H4 are the "surprising" hypotheses relative to the naive prior that
PQC is strictly worse on every axis. Early single-transaction measurements
during development (see `results/`) showed ML-DSA-65 sign (~0.4ms) and
verify (~0.15ms) *faster* than ECDSA sign (~2.4-3.7ms) and verify
(~2.6-3.7ms) on this project's build/hardware — consistent with H4 — but
this is a per-transaction spot check, not the full statistically-powered
sweep; see `results/aggregate_stats.csv` and
`results/significance_vs_control.csv` for the actual reported result.

## 6. Statistical methodology

- 5 repetitions per (configuration × concurrency) cell.
- The first 5% of requests in each cell are discarded as connection-pool /
  JIT warm-up before computing statistics (`analysis/aggregate.py
  --warmup-fraction`), skipped for cells with fewer than 20 total requests.
- Mean, median, standard deviation, p95, and p99 are all reported — not
  mean alone — because crypto/network latency distributions are
  right-skewed and an SLA-relevant claim (sub-100ms p99) needs percentile
  data.
- A non-parametric Mann-Whitney U test compares each protected
  configuration's RTT distribution against control at the same concurrency
  level, since normality of latency distributions should not be assumed.

## 7. Known limitations

- Benchmarked on a single, possibly resource-constrained host (see
  `results/sweep_summary.json` for the actual host's core count and
  observed error rates at concurrency=1000); absolute latency numbers are
  hardware-dependent, but relative overhead *ratios* between configurations
  on the same host should reproduce.
- The `--concurrency 1000` cells on a single-core host saturate the
  *unprotected control* configuration's own capacity, not just the crypto
  layer — per the design doc's own risk register, this is treated as a
  valid "overhead under contention" result and reported as such, not
  discarded.
- liboqs reference (non-AVX2-optimized where unavailable) implementations
  are used; a production deployment on server-class hardware with AVX2/AVX-512
  available may see different absolute ML-KEM/ML-DSA timings.
- Single hardware profile; no CIFAR-10/larger-payload sensitivity run is
  included in this pass (see README "Next steps").
