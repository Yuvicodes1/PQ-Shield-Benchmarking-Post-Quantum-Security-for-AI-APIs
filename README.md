# PQ-Shield: Security-Performance Benchmarking of PQC Algorithms for AI API Protection

PQ-Shield is an empirical measurement framework for the operational cost of
migrating a real-time AI inference API to NIST post-quantum cryptography
(PQC). It wraps the same FastAPI digit-classifier inference workload in
three cryptographic configurations, subjects each to concurrency sweeps and
two adversarial threat scenarios (harvest-now-decrypt-later, active
man-in-the-middle tampering), and produces a quantitative, weighted
security/performance trade-off matrix.

| Configuration | Key establishment | Response signature | Purpose |
|---|---|---|---|
| Control | none | none | Unprotected zero-overhead reference |
| A — Classical | RSA-2048-OAEP | ECDSA P-256 | Current classical baseline |
| B — Hybrid | ML-KEM-768 (FIPS 203) | ECDSA P-256 | Incremental PQC migration path |
| C — Full PQC | ML-KEM-768 (FIPS 203) | ML-DSA-65 (FIPS 204) | Fully quantum-resistant |

The inference workload is a 100-tree scikit-learn RandomForest trained on
the UCI Optical Recognition of Handwritten Digits dataset (`load_digits`,
1,797 samples, 64 features, 10 classes, ~96% test accuracy). Model accuracy
is not the point — the model exists to produce realistic small-request /
small-response JSON payloads (≈345B request / ≈93B response) for the
crypto wrappers to protect. See `docs/DESIGN.md` for the full protocol
design, hypotheses (H1–H4), and divergences from the original Review 1
proposal.

## What's implemented

- **`crypto/oqs_adapter.py`** — a from-scratch ctypes binding directly to
  a locally built liboqs shared library (ML-KEM-768 + ML-DSA-65 only), with
  a startup self-test. No `liboqs-python` dependency, no system-wide install.
- **Three full crypto configurations** (`crypto/classical.py`,
  `crypto/hybrid.py`, `crypto/full_pqc.py`) sharing a common interface
  (`crypto/base.py`) and the same AES-256-GCM symmetric layer
  (`crypto/aead.py`, HKDF-SHA256 keyed).
- **13 passing protocol tests** (`tests/test_crypto_roundtrip.py`) covering
  full round-trips and tamper detection (corrupted ciphertext, corrupted
  signature, substituted message) for all three configurations.
- **Four FastAPI servers**: `api/server.py` (control) and
  `api/server_config_{a,b,c}.py` (protected), all sharing
  `api/secure_app.py`'s handshake + predict endpoint logic and
  `api/model_service.py`'s inference code, so the crypto wrapper is the
  only thing that differs between server processes.
- **CLI clients** (`api/client.py`, `client_hybrid.py`, `client_full_pqc.py`)
  and a shared async transaction helper (`api/secure_client.py`).
- **Benchmark orchestrator** (`bench/orchestrator.py` +
  `bench/runner.py`) that launches each server fresh, sweeps concurrency ×
  repetitions, and writes one CSV row per request.
- **HNDL threat script** (`threats/hndl_capture.py`) measuring stored byte
  volume per configuration, explicitly distinguishing "bytes an adversary
  must store" from "bytes eventually decryptable under a future CRQC."
- **MITM threat harness** (`threats/mitm_harness.py`, a small `aiohttp`
  proxy) and driver (`threats/mitm_experiment.py`) that tamper with either
  the response ciphertext or the signature field and measure detection
  rate/latency, isolating AEAD-layer detection from signature-layer
  detection.
- **Analysis layer**: `analysis/aggregate.py` (mean/median/std/p95/p99 +
  Mann-Whitney U significance vs. control), `analysis/tradeoff_matrix.py`
  (the weighted composite-score decision matrix, reported at three
  weightings), `analysis/figures.py` (the full paper figure set), and
  `analysis/plot_metrics.py` (a quick smoke-test comparison chart).
- **Payload profiles** (`model/profiles/*`) — the request/response shape
  every server dispatches through, swappable per process via
  `PQ_SHIELD_PAYLOAD_PROFILE`: `tabular_small` (the digit classifier above,
  default), `image_cnn` (a ~4KB image payload against real NumPy
  convolution compute), `embedding`, and `llm_completion`, for the
  payload-shape sensitivity question in `docs/DESIGN.md`.
- **Token streaming** (`crypto/streaming.py`, `POST
  /secure/predict/stream`, `api/secure_streaming_client.py`,
  `model/streaming_backends/*`) — SSE token-by-token responses with three
  signing strategies (buffer-and-sign, per-chunk, hash-chain); see
  `docs/STREAMING.md`.
- **Primitive validation** (`validation/`) — `primitive_bench.py` and
  `spec_conformance.py` check the liboqs-backed ML-KEM-768/ML-DSA-65
  implementation against known-answer test vectors, independent of the
  benchmark/protocol layer above.
- **Dockerfile** for reproducible builds (liboqs build + pinned deps +
  self-test + pytest, all run at image-build time).

## Prerequisites

- Python 3.11+ (developed and tested on 3.12).
- CMake, Ninja, a C compiler, OpenSSL headers, and Git, to build liboqs
  from source. On Ubuntu/Debian: `apt install build-essential cmake
  ninja-build libssl-dev git`. On macOS: Xcode Command Line Tools plus
  `brew install cmake ninja`.

## Setup

```bash
git clone <this-repo>
cd pq-shield

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

bash scripts/install_oqs.sh
# prints: export PQ_SHIELD_OQS_LIB=<repo>/oqs-prefix/lib/liboqs.so
export PQ_SHIELD_OQS_LIB=<repo>/oqs-prefix/lib/liboqs.so   # add to your shell profile

python -m model.train
python -m pytest -q   # 13 passed
```

`install_oqs.sh` clones liboqs and builds *only* ML-KEM-768 and ML-DSA-65
(`OQS_MINIMAL_BUILD`), which compiles in under a minute on one core. To
point at a different liboqs build (system-wide, or a full build with every
algorithm), skip the script and set `PQ_SHIELD_OQS_LIB` to that library's
absolute path directly.

## Run a single server and make a prediction

```bash
# Control (unprotected)
uvicorn api.server:app --port 8000
curl -X POST localhost:8000/predict -H "Content-Type: application/json" \
  -d '{"input":[0,0,5,13,9,1,0,0,0,0,13,15,10,15,5,0,0,3,15,2,0,11,8,0,0,4,12,0,0,8,8,0,0,5,8,0,0,9,8,0,0,4,11,0,1,12,7,0,0,2,14,5,10,12,0,0,0,0,6,13,10,0,0,0]}'
```

```bash
# Configuration A (classical)
uvicorn api.server_config_a:app --port 8000
python -m api.client --url http://127.0.0.1:8000

# Configuration B (hybrid)
uvicorn api.server_config_b:app --port 8000
python -m api.client_hybrid --url http://127.0.0.1:8000

# Configuration C (full PQC)
uvicorn api.server_config_c:app --port 8000
python -m api.client_full_pqc --url http://127.0.0.1:8000
```

Each protected client performs a full transaction (handshake → establish
session key → AES-GCM encrypt request → POST → AES-GCM decrypt response →
verify signature) and prints every timing field plus `valid_signature`.

## Run the full benchmark matrix

```bash
python -m bench.orchestrator \
  --configs control,classical,hybrid,full-pqc \
  --concurrency 10,100,1000 \
  --repetitions 5 \
  --requests-per-concurrency 5 \
  --min-requests 50
```

The orchestrator starts each server fresh (own process, own port), waits
for `/healthz`, runs every (concurrency × repetition) cell, writes
`results/raw/{config}-c{concurrency}-r{repetition}.csv`, then stops that
server before moving to the next configuration — no two configurations
ever share a process or contend for the same core simultaneously.
`--requests-per-concurrency` sets `requests = concurrency *
requests_per_concurrency` per cell (`--min-requests` is a floor for
low-concurrency cells); the design doc's convention is 10× concurrency —
lower it if your machine is core-constrained (a single-core sandbox, for
example, needs 30–45 minutes for the full 10×`concurrency`,
3-concurrency-level, 5-repetition, 4-configuration matrix; scale
accordingly).

For a single ad-hoc cell instead of the full matrix (server already
running separately):

```bash
python -m bench.runner --configuration full-pqc --concurrency 100 \
  --requests 500 --repetition 1 --server-pid <server_pid> \
  --output results/raw/full-pqc-c100-r1.csv
```

`--server-pid` attaches CPU%/RSS sampling to that process for the duration
of the run (`crypto/instrumentation.ResourceSampler`).

## Run the threat experiments

**HNDL (passive capture, 1000 requests):**

```bash
uvicorn api.server_config_c:app --port 8000 &
python -m threats.hndl_capture --configuration full-pqc \
  --url http://127.0.0.1:8000 --requests 1000 \
  --output results/hndl/full-pqc-hndl.csv
```

**MITM (active tamper injection + detection):**

```bash
uvicorn api.server_config_c:app --port 8000 &
python -m threats.mitm_harness --upstream http://127.0.0.1:8000 \
  --listen-port 8080 --tamper-target ciphertext &
python -m threats.mitm_experiment --configuration full-pqc \
  --proxy-url http://127.0.0.1:8080 --requests 100 \
  --tamper-target ciphertext \
  --output results/mitm/full-pqc-mitm-ciphertext.csv
```

Or run both threat scripts for one configuration against an already-running
server in one step:

```bash
uvicorn api.server_config_a:app --port 8001 &
bash scripts/run_threat_experiments.sh classical 8001
```

`--tamper-target ciphertext` corrupts the AES-GCM response body (caught at
the AEAD authentication layer, before signature verification is reached);
`--tamper-target signature` corrupts only the signature field, isolating
ECDSA vs. ML-DSA-65 tamper-detection latency specifically (this is the
number RQ4/H4 is about).

## Analyze results

```bash
python -m analysis.aggregate           # mean/median/std/p95/p99 + Mann-Whitney U vs. control
python -m analysis.tradeoff_matrix     # weighted composite security/performance score
python -m analysis.figures             # full paper figure set -> outputs/*.png
python -m analysis.plot_metrics        # quick smoke-test comparison chart
```

`analysis/aggregate.py` discards the first 5% of requests per cell as
warm-up (`--warmup-fraction` to change) and reports a non-parametric
Mann-Whitney U test comparing each protected configuration's RTT
distribution against control at each concurrency level, since crypto/network
latency distributions are right-skewed and should not be assumed normal.

`analysis/tradeoff_matrix.py` reports the composite score
`w_sec * security_score(config) - w_perf * normalized_latency_overhead`
at three weightings (security-priority, balanced, performance-priority)
rather than one arbitrary weighting — see `docs/DESIGN.md` §5 for the
explicit, defended `security_score` ordinal mapping.

## Payload profiles (beyond the digit classifier)

Every server dispatches its request/response shape through a pluggable
`model/profiles/*` profile (`model/profiles/registry.py`), selected once per
process via `PQ_SHIELD_PAYLOAD_PROFILE` (default: `tabular_small`, the
64-feature digit classifier used throughout this README). `python -m
bench.orchestrator --payload-profile {tabular_small,image_cnn,embedding,
llm_completion}` sweeps a different workload shape end-to-end — larger
request/response payloads change the crypto-overhead-to-payload-size ratio,
which is the sensitivity question raised in `docs/DESIGN.md`.

## Preparing a live demo (e.g. a review/panel presentation)

```bash
bash scripts/preflight_check.sh   # verifies self-test, model, tests, ports, data — fix any ❌
bash scripts/run_webapp.sh        # launch the dashboard, warm it up yourself first
```

See `docs/PRESENTER_GUIDE.md` for a page-by-page demo script with timing,
talking points anchored to this project's actual measured numbers, and
answers to likely panel questions (including how to honestly present a
counterintuitive or still-being-verified result rather than overclaiming it).

## Streaming signatures (LLM-style token streams)

The above benchmarks single-shot JSON responses. For token-by-token SSE
streaming responses — the shape a real chat-completion API actually uses —
`POST /secure/predict/stream` (`api/secure_app.py`) streams Server-Sent
Events instead of one JSON body. See `docs/STREAMING.md`, which covers three
signing strategies (buffer-and-sign, per-chunk, hash-chain), their
time-to-first-token and signature-byte-overhead trade-offs, and how to run
the real vs. synthetic generation backends (`model/streaming_backends/*`;
`requirements-streaming.txt` for the optional real-model dependencies).

## Docker

```bash
docker build -t pq-shield .
docker run --rm -p 8000:8000 pq-shield
# or, to run a full sweep with results persisted to the host:
docker run --rm -v "$(pwd)/results:/app/results" pq-shield \
  python -m bench.orchestrator --configs control,classical,hybrid,full-pqc \
  --concurrency 10,100,1000 --repetitions 5
```

The image builds liboqs from source, installs pinned dependencies, trains
the model, and runs the crypto self-test plus the full pytest suite at
*build* time — a broken build never ships.

## Interactive dashboard (Streamlit)

```bash
pip install -r requirements.txt   # includes streamlit + plotly
bash scripts/run_webapp.sh        # http://localhost:8501
```

Four pages:

- **Live Demo** — pick a configuration and a test digit, click "Send
  request," and watch a real handshake → establish → AEAD-encrypt → POST →
  AEAD-decrypt → verify transaction run against an actual server the page
  starts on demand (ports 8100–8103, separate from the CLI's default 8000
  so the two never collide). Includes a live tamper toggle (corrupt
  ciphertext or signature) that demonstrates detection in real time —
  corrupting the ciphertext is caught independently at both the AEAD layer
  and the signature layer, since the tampered envelope no longer matches
  what was signed.
- **Benchmark Runner** — runs a scoped `bench.orchestrator` sweep directly
  from the browser (small concurrency/repetition values recommended for an
  interactive session; use the CLI for the full paper-scale matrix).
- **Results Dashboard** — interactive Plotly charts (RTT vs. concurrency,
  overhead decomposition, bytes per request) and tables (aggregate stats,
  Mann-Whitney U significance) built from whatever is currently in
  `results/raw/`, plus a live security/performance trade-off matrix with a
  slider for the security-weight/performance-weight trade-off.
- **Threat Scenarios** — HNDL storage-growth and MITM detection results
  from disk, plus buttons to run either experiment on demand against a
  live server and save the result.

All four pages import directly from `crypto/`, `api/`, `bench/`,
`threats/`, and `analysis/` — there is no separate "demo" implementation of
the protocol or the statistics; the dashboard is a thin interactive layer
over the same code the CLI and the paper's results are built from.

## Repository structure

```
pq-shield/
├── crypto/
│   ├── oqs_adapter.py       # ctypes bindings to liboqs (ML-KEM-768, ML-DSA-65)
│   ├── aead.py                # AES-256-GCM + HKDF session-key derivation
│   ├── base.py                 # shared ServerCryptoConfig / ClientCryptoConfig interface
│   ├── classical.py            # Config A
│   ├── hybrid.py                # Config B
│   ├── full_pqc.py              # Config C
│   ├── registry.py               # name -> crypto class lookup
│   ├── instrumentation.py         # Timer, ResourceSampler (CPU%/RSS)
│   └── streaming.py                # SSE signing strategies (buffer/per-chunk/hash-chain)
├── model/
│   ├── train.py                 # trains + serializes the RandomForest
│   ├── artifacts/                # model.pkl, model_metadata.json (gitignored)
│   ├── profiles/                 # tabular_small, image_cnn, embedding, llm_completion
│   └── streaming_backends/        # synthetic + real (llama.cpp/transformers) token backends
├── api/
│   ├── model_service.py         # dispatches to the active payload profile
│   ├── schemas.py                 # pydantic request/response models
│   ├── server.py                   # control (unprotected)
│   ├── secure_app.py                # shared handshake+predict(+stream) endpoint logic
│   ├── server_config_{a,b,c}.py      # thin per-config wrappers
│   ├── secure_client.py                # shared async client transaction logic
│   ├── secure_streaming_client.py       # client-side SSE stream consumption
│   ├── async_bridge.py                   # sync generator -> async iterator bridge
│   ├── _client_cli.py                     # shared CLI plumbing
│   └── client{,_hybrid,_full_pqc}.py       # per-config CLI entrypoints
├── bench/
│   ├── runner.py                # single-cell async load generator
│   ├── orchestrator.py           # full matrix: manages server lifecycle + sweep
│   └── streaming_runner.py        # streaming-mode load generator
├── threats/
│   ├── hndl_capture.py          # Threat Scenario 1
│   ├── mitm_harness.py           # Threat Scenario 2 -- tampering proxy
│   └── mitm_experiment.py         # Threat Scenario 2 -- driver + detection stats
├── validation/                   # ML-KEM-768/ML-DSA-65 vs. known-answer test vectors
│   ├── primitive_bench.py
│   ├── reference_data.py
│   └── spec_conformance.py
├── analysis/
│   ├── aggregate.py              # summary stats + Mann-Whitney U
│   ├── tradeoff_matrix.py         # weighted composite decision matrix
│   ├── figures.py                  # full paper figure set
│   ├── plot_metrics.py              # quick comparison chart
│   └── streaming_analysis.py         # time-to-first-token / signing-overhead analysis
├── webapp/
│   ├── bootstrap.py               # repo-root sys.path + .env loading (import first, always)
│   ├── server_manager.py           # demo server lifecycle (ports 8100-8103)
│   ├── demo_transaction.py          # tamper-capable live transaction logic
│   ├── data_loader.py                # cached results loading for the dashboard
│   └── ai_summary.py                  # on-demand Claude-generated dashboard summary
├── pages/                        # Streamlit multipage app (Live Demo, Benchmark Runner,
│                                    Results Dashboard, Threat Scenarios)
├── app.py                        # Streamlit entrypoint (Home page)
├── tests/test_crypto_roundtrip.py  # 13 protocol tests (+ payload-profile/streaming/validation tests)
├── scripts/
│   ├── install_oqs.sh            # builds liboqs (minimal, ML-KEM-768 + ML-DSA-65)
│   ├── run_threat_experiments.sh  # HNDL + MITM convenience wrapper
│   └── preflight_check.sh          # pre-demo sanity check (self-test, model, tests, ports)
├── docs/
│   ├── DESIGN.md                 # protocol design, hypotheses, divergences from proposal
│   ├── STREAMING.md               # SSE signing strategies + backend setup
│   ├── PRESENTER_GUIDE.md          # page-by-page live-demo script
│   └── diagrams/                   # architecture SVGs referenced from ARCHITECTURE.md
├── results/                      # raw CSVs, aggregates, trade-off matrix (gitignored)
├── outputs/                       # generated figures (gitignored)
└── Dockerfile
```

## Current status / next steps

Implemented and passing: crypto layer, protocol tests, all four servers,
CLI clients, benchmark orchestrator, HNDL and MITM threat scripts, the
full analysis/figures pipeline, the pluggable payload-profile system
(`model/profiles/*`), SSE token streaming with three signing strategies
(`crypto/streaming.py`, `docs/STREAMING.md`), and primitive-level validation
against known-answer test vectors (`validation/`). A full A/B/C/control × {10,100,1000}
concurrency × 5-repetition sweep and the HNDL/MITM experiments have been
run once end-to-end on the development host; see `results/` for the actual
output and `docs/DESIGN.md` §7 for host-specific caveats (this repo was
developed on a single-core sandbox, so absolute latency numbers there are
not representative of production hardware — re-run the sweep on your
target hardware before citing absolute numbers, though relative overhead
ratios between configurations are expected to reproduce).

Remaining for the full Review 2 / paper-ready deliverable:

1. Re-run the full matrix on multi-core, non-sandboxed hardware for
   production-representative absolute latency numbers.
2. `model/profiles/image_cnn.py` covers the larger-payload sensitivity
   question with a real (untrained, deterministically-seeded) NumPy conv
   net rather than the CIFAR-10-trained CNN the Review 1 proposal
   envisioned — swap in a trained CIFAR-10 model there if classification
   accuracy itself needs to be defensible, not just the payload shape/cost.
3. Expand `analysis/figures.py`'s CPU/RSS heatmap (currently a no-op
   placeholder — resource sampling is wired into `bench/runner.py`'s
   single-cell mode via `--server-pid` but not yet threaded through the
   full-matrix `bench/orchestrator.py` path).
4. Push the `--reuse-handshake` "warm connection" variant through the full
   sweep as a secondary result, per `docs/DESIGN.md` §3.
5. Publish to IEEE Access / an ACM CCS workshop per the Review 1 proposal's
   target venue, and tag a release for the open-source artifact.

## Security scope

These cryptographic wrappers are an application-layer benchmarking harness,
not a replacement for TLS. In a real deployment, run the API behind
authenticated TLS and use authenticated server-key distribution or
certificate pinning. The handshake endpoint in this prototype intentionally
exposes fresh ephemeral public key material on every call, unauthenticated,
so the benchmark can measure a fresh exchange per transaction by default —
this is appropriate for a benchmarking harness and inappropriate for a
production authentication scheme as-is.
