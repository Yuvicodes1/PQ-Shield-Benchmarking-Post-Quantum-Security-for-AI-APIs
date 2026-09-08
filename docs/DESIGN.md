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

**A note on baselines**: H1's "vs. classical" framing and the composite
score's `normalized_latency_overhead` (Phase 6) are not always measured
against the same reference. The concurrency sweep has a genuine unprotected
`control` leg, and every reported number for it — the Mann-Whitney
significance test in §6 below and the trade-off matrix's composite score —
is computed relative to `control`, not `classical`, since that's the
zero-overhead reference point. The streaming sweep
(`bench/streaming_runner.py`) has no `control` leg at all — it only
exercises `classical`/`hybrid`/`full_pqc` — so the same two computations,
when applied to streaming data, fall back to `classical` as the nearest
real baseline instead. This is a genuine methodological difference between
the two experiment types, not an implementation detail: a streaming
overhead or significance number and a concurrency-sweep one are not
baseline-equivalent, and the Results Dashboard labels which baseline a
given number uses rather than leaving it implicit (see
`analysis.aggregate.resolve_baseline_config`, the one place this resolution
logic lives).

**Streaming security score**: the composite score's `security_score(config)`
term (Phase 6) is a single categorical number for the concurrency sweep —
`SECURITY_SCORES = {classical: 0.0, hybrid: 0.8, full_pqc: 1.0}`, defended
above and unchanged by any of this. For a streaming run, signing *strategy*
is itself a measured, security-relevant choice the concurrency sweep has no
equivalent of: `per_chunk` catches a dropped/reordered chunk on the very
next chunk, `hash_chain` defers that guarantee to the terminating signature
(trading a real, measured exposure window for cheaper signing), and
`buffer_and_sign` has no exposure window at all by construction (nothing is
delivered before the end). `analysis.tradeoff_matrix.streaming_security_score`
blends this measured **sequence-integrity exposure resistance** — `1 -`
mean fraction of the response delivered before a
`threats/streaming_mitm_experiment.py` drop/reorder attack is caught, per
`(config, strategy)` — into the existing categorical score:

```
streaming_security_score(config, strategy) =
    (1 - exposure_share) * SECURITY_SCORES[config]
    + exposure_share * sequence_integrity_resistance(config, strategy)
```

This is a blend, not a third weighted term added to the composite formula
— `w_sec`/`w_perf` still sum to 1 exactly as before, and the concurrency
sweep's composite score is completely unaffected (this function is never
called for it). `exposure_share` defaults to **0.3**: exposure-window risk
is real but secondary to the categorical confidentiality/authenticity
distinction that dominates the non-streaming score too, and a byte-
corruption tamper (the ordinary MITM threat) is still caught immediately by
AES-GCM regardless of strategy — only sequence *reordering/dropping*
depends on it. The Results Dashboard exposes `exposure_share` as a slider
(default 0.3) on the streaming trade-off panel rather than hard-coding it,
same rationale as `w_sec` itself: this is a judgment call a reader should
be able to adjust, not a hidden constant.

**Why MITM detection rate is *not* in the score**: a correctly-implemented
ECDSA and a correctly-implemented ML-DSA-65 should both detect a tampered
byte close to 100% of the time, near-term — `analysis.security_validation
.validate_authenticity_near_term` checks this against real
`results/mitm/*-summary.json` data and confirms it holds (uniformly ≥99%
detection across every config with data, as of this writing). That
near-term similarity is *expected*, not informative — the real difference
`SECURITY_SCORES`' authenticity ordering captures is whether a forgery
could be produced *at all* once a CRQC exists, which a detection-rate
number from today's hardware cannot measure. Folding detection rate into
the score would erase that categorical distinction (Full PQC resists
*future* quantum forgery; Hybrid does not) behind a near-term rate that
doesn't differentiate the configs at all. See
`analysis/security_validation.py` and the "Security-Score Assumption
Validation" section of `pages/5_🔬_Cryptographic_Validation.py`, which
re-runs both checks (confidentiality *and* authenticity) against whatever
Threat Scenarios data is on disk, rather than asserting either axis once
and never re-checking it.

H3 and H4 are the "surprising" hypotheses relative to the naive prior that
PQC is strictly worse on every axis. Early single-transaction measurements
during development (see `results/`) showed ML-DSA-65 sign (~0.4ms) and
verify (~0.15ms) *faster* than ECDSA sign (~2.4-3.7ms) and verify
(~2.6-3.7ms) on this project's build/hardware — consistent with H4 — but
this is a per-transaction spot check, not the full statistically-powered
sweep; see `results/aggregate_stats.csv` and
`results/significance_vs_control.csv` for the actual reported result.

H3 above is measured for one small, fixed-size response. For a streamed
response, the same key-establishment session is reused across every chunk
of a potentially long-running stream, which makes H3's exposure grow with
response length rather than stay fixed-size — see `docs/STREAMING.md`
§10 for the streaming-specific capture and measured numbers
(`threats/streaming_hndl_experiment.py`). This is the same H3 finding, not
a new one, made length-dependent by streaming's protocol shape.

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
  (Streaming figures use the same test against `classical` instead, since
  the streaming sweep has no `control` leg — see "A note on baselines"
  in §5 and `docs/STREAMING.md`.)

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
