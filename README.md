# PQ-Shield: Post-Quantum Signature Schedules for Streaming LLM Inference

PQ-Shield is a measurement study of what migrating a protected AI inference API
to NIST post-quantum cryptography costs, in milliseconds and bytes, and what it
buys against passive and active attackers. It wraps a real FastAPI inference
service — a RandomForest classifier for request/response traffic and a
Llama-3.2-3B model for token streaming — in seven protection configurations,
and measures them under load, on emulated networks, with session reuse, and
under attack.

The main finding: for a streamed LLM response, the post-quantum cost lies in the
**signature schedule**, not the key exchange. Signing every chunk with ML-DSA-65
adds 135,669 B to a 200-token response; one hash-chain signature adds 3,309 B but
leaves the response unverified until it ends. A hash chain checkpointed every
*k* chunks spans that range, and *k* sets how much unverified text a user has
seen when an attack is caught.

PQ-Shield is an **application-layer emulation of protected inference
transactions, not a TLS implementation**. The paper, its figures and tables,
and the response to reviewers are in [`paper/`](paper/).

| Code | Configuration | Key establishment | Signature | Role |
|---|---|---|---|---|
| — | Control | none | none | Unprotected reference (one request) |
| — | Control-2RT | none | none | Same two HTTP requests as a protected transaction, no crypto: protected − Control-2RT = cryptographic overhead |
| A | Classical-RSA | RSA-2048-OAEP, key generated per handshake | ECDSA P-256 | Legacy worst case |
| A′ | Classical-ECDHE | X25519 | ECDSA P-256 | Realistic classical baseline |
| B | Hybrid | ML-KEM-768 (FIPS 203) | ECDSA P-256 | Post-quantum key exchange |
| B′ | Hybrid-KEX | X25519MLKEM768 | ECDSA P-256 | Deployed hybrid group; hedged against an ML-KEM break |
| C | Full PQC | ML-KEM-768 | ML-DSA-65 (FIPS 204) | Post-quantum on both axes |
| C′ | Hybrid-KEX-PQ | X25519MLKEM768 | ML-DSA-65 | Post-quantum on both axes and hedged |

All protected configurations share AES-256-GCM with an HKDF-SHA256 session key;
only the asymmetric primitives differ. An optional **authenticated handshake**
(server signs the handshake transcript with an identity key the client pins)
is available for every configuration.

## What's implemented

- **Crypto** (`crypto/`) — a from-scratch ctypes binding to a locally built
  liboqs (ML-KEM-768, ML-DSA-65; `oqs_adapter.py`), the seven configurations
  behind one interface (`base.py`, `registry.py`), AES-256-GCM + HKDF
  (`aead.py`), optional handshake authentication (`handshake_auth.py`), and
  timers that record wall-clock and thread-CPU time (`instrumentation.py`).
- **Streaming** (`crypto/streaming.py`, `POST /secure/predict/stream`) —
  buffer-and-sign, per-chunk, and hash-chain signing with optional checkpoints
  every *k* chunks. Every signed message binds a role label, the session, and
  the chunk position; every stream ends with a signed length record; the
  client requires that record and enforces the checkpoint schedule it requested.
- **Servers and clients** (`api/`) — one FastAPI process per configuration
  (`server.py`, `server_config_*.py`, shared `secure_app.py`), async clients
  with session resumption and identity pinning (`secure_client.py`,
  `secure_streaming_client.py`).
- **Benchmarks** (`bench/`) — concurrency sweeps (`orchestrator.py`,
  `runner.py`), streaming sweeps (`streaming_runner.py`), byte-level network
  emulation (`netem_proxy.py`), and `paper_runs.py`, which reproduces every
  experiment in the paper and records run IDs in `results/paper_runs.json`.
- **Threat experiments** (`threats/`) — harvest-now-decrypt-later capture
  (single transaction and streaming), response tampering, stream sequence
  attacks, a 500-trials-per-cell **attack campaign** with adaptive checkpoint
  attacks and a false-rejection baseline (`streaming_attack_campaign.py`), and
  **key substitution** against unauthenticated and pinned handshakes
  (`key_substitution.py`).
- **Validation** (`validation/`) — all **130 NIST ACVP vectors** reproduced,
  including ML-DSA-65 key generation and signing byte for byte (`nist_kat.py`);
  FIPS size conformance; primitive benchmarks; and a signing-cost diagnostic
  (back-to-back vs. spaced vs. busy vs. efficiency cores; `contention_check.py`).
- **Analysis** (`analysis/paper_figures.py`) — every figure and table in the
  paper, with repetition-level statistics (two-stage bootstrap CIs, Cliff's δ,
  Holm-corrected Mann–Whitney on repetition medians, ±5% equivalence tests),
  failure analysis, and a weight-free dominance table.
- **Dashboard** (`app.py`, `views/`, `webapp/`) — see below.

## Prerequisites

- Python 3.11+ (developed on 3.13).
- CMake, Ninja, a C compiler, OpenSSL headers, and Git, to build liboqs from
  source. Ubuntu/Debian: `apt install build-essential cmake ninja-build
  libssl-dev git`. macOS: Xcode Command Line Tools plus `brew install cmake ninja`.
- Optional, for real LLM streaming: `pip install -r requirements-streaming.txt`
  and a GGUF model (the paper uses Llama-3.2-3B-Instruct Q4_K_M); see
  `docs/STREAMING.md`.

## Setup

```bash
git clone <this-repo>
cd pq-shield
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

bash scripts/install_oqs.sh
export PQ_SHIELD_OQS_LIB=<repo>/oqs-prefix/lib/liboqs.so   # printed by the script; add to your shell profile

python -m model.train
python -m pytest -q
# 205 passed, 4 failed -- the 4 failures are legacy tests (test_classical_roundtrip.py,
# test_full_pqc.py, test_hybrid_roundtrip.py) written against an older schema.
```

`install_oqs.sh` builds only ML-KEM-768 and ML-DSA-65 (`OQS_MINIMAL_BUILD`). To
use another liboqs build, set `PQ_SHIELD_OQS_LIB` to its absolute path.
A repo-root `.env` (gitignored) can hold `PQ_SHIELD_OQS_LIB`,
`PQ_SHIELD_LLAMA_MODEL_PATH`, `PQ_SHIELD_STREAMING_BACKEND=llama_cpp`, and
`ANTHROPIC_API_KEY` (dashboard AI summaries).

## Reproduce the paper

```bash
python -m bench.paper_runs                 # every experiment, in order (several hours)
python -m bench.paper_runs --steps 16,17   # a subset (see the step list in bench/paper_runs.py)
python -m analysis.paper_figures           # figures, tables, key_numbers.md -> paper/
cd paper && tectonic -X compile pq_shield_journal.tex
```

`paper_runs.py` runs each step on one host, archives earlier threat/validation
results, records each sweep's run ID and the software environment
(`paper/environment.json`), and keeps going if a step fails. Steps 1–13 are the
original experiments; steps 14–21 are the second review round (signing-cost
diagnostic, Hybrid-KEX-PQ concurrency, streaming and checkpoint sweeps with CPU
time, attack campaign, key substitution, authenticated-handshake cost, HNDL for
Hybrid-KEX-PQ). Keep the machine otherwise idle and on AC power while it runs.

## Run a single server

```bash
uvicorn api.server:app --port 8000                       # Control (also serves Control-2RT's GET /handshake)
uvicorn api.server_config_a:app --port 8000              # A  Classical-RSA
uvicorn api.server_config_ecdhe:app --port 8000          # A′ Classical-ECDHE
uvicorn api.server_config_b:app --port 8000              # B  Hybrid
uvicorn api.server_config_hybridkex:app --port 8000      # B′ Hybrid-KEX
uvicorn api.server_config_c:app --port 8000              # C  Full PQC
uvicorn api.server_config_hybridkexpq:app --port 8000    # C′ Hybrid-KEX-PQ
PQ_SHIELD_AUTH_HANDSHAKE=1 uvicorn api.server_config_c:app --port 8000   # with handshake authentication

python -m api.client --url http://127.0.0.1:8000           # CLI client for A (client_hybrid, client_full_pqc for B, C)
```

## Run individual experiments

```bash
# Concurrency sweep (each configuration's server is started fresh, swept, stopped)
python -m bench.orchestrator --configs control-2rt,classical-ecdhe,hybrid,full-pqc \
  --concurrency 10,100,1000 --repetitions 5
#   --network-profile {localhost,metro,wan,mobile}   byte-level network emulation
#   --requests-per-handshake 100                     session resumption
#   --payload-profile {tabular_small,image_cnn,embedding,llm_completion}
#   --auth-handshake                                 authenticated handshake

# Streaming sweep (real Llama with PQ_SHIELD_STREAMING_BACKEND=llama_cpp, else synthetic)
python -m bench.streaming_runner --configs hybrid,full-pqc --strategies per_chunk,hash_chain \
  --max-tokens 200 --chunk-size-tokens 5 --repetitions 5 --checkpoint-intervals 0,1,5,10

# Threats
python -m threats.streaming_attack_campaign --trials 500 --pool 10     # stream integrity, static + adaptive
python -m threats.key_substitution --trials 300                        # full man-in-the-middle
python -m threats.streaming_hndl_experiment --configs classical,full-pqc --max-tokens 50,200,500,2000
bash scripts/run_threat_experiments.sh classical 8001                  # HNDL + tampering, one config

# Validation
python -m validation.nist_kat --output results/validation/nist_kat.json   # 130/130 ACVP vectors
python -m validation.contention_check                                     # signing cost by calling pattern
python -m validation.primitive_bench --output results/validation/primitive_bench.json
```

Latency is end-to-end (`total_ms`: handshake + protected request). At high
concurrency on a single host, client and server share the CPU; the paper draws
equivalence conclusions at 10 connections only.

## Docker

```bash
docker build -t pq-shield .
docker run --rm -p 8501:8501 pq-shield streamlit run app.py --server.port 8501 --server.address 0.0.0.0
docker run --rm -v "$(pwd)/results:/app/results" pq-shield python -m bench.orchestrator --concurrency 10 --repetitions 2
```

The image builds liboqs from source, installs pinned dependencies, trains the
model, and runs the crypto self-test at build time.

## Interactive dashboard (Streamlit)

```bash
pip install -r requirements.txt   # includes streamlit + plotly
bash scripts/run_webapp.sh        # http://localhost:8501
```

Seven pages in three groups (`app.py` routes to `views/`; theme in
`.streamlit/config.toml`, light and dark; shared styling in `webapp/ui.py`):

**Overview**
- **Home** — headline results computed from the result files, the seven
  configurations with their security properties, and an environment check.
- **Key findings** — the paper's results from its own runs
  (`results/paper_runs.json`), via the same code that builds the paper's
  tables: an interactive signature-schedule dial (bytes vs. exposure for any
  checkpoint interval), the signing-cost diagnostic, the stream-attack
  campaign, key substitution and the cost of handshake authentication,
  key establishment against the matched protocol control, and a no-weights
  decision explorer (pick the security properties you need and the workload).

**Interactive**
- **Live demo** — stream a real Llama response through any configuration
  and watch each chunk get decrypted and verified: text appears muted until
  a verified signature covers it. Choose the signing strategy and checkpoint
  interval, and simulate an on-path attacker (bit flips, drop, reorder,
  duplicate, truncate, strip checkpoints). Also a single-request demo with
  tampering. Demo servers run on ports 8100–8106 with handshake
  authentication enabled.
- **Benchmark runner** — scoped concurrency sweeps (optionally with the
  authenticated handshake) and streaming sweeps (with checkpoint intervals)
  from the browser.

**Evidence**
- **Results explorer** — any concurrency or streaming run on disk, plus a
  "Paper runs" source that combines the paper's runs exactly as the paper
  does (latest run per configuration). Repetition-level comparisons with
  bootstrap CIs; per-signature CPU time for streaming runs.
- **Threat lab** — harvest-now-decrypt-later exposure, tampering, stream
  sequence attacks (with checkpoints), and key substitution, each with saved
  results and a live run.
- **Validation** — all 130 NIST ACVP vectors, signature counts vs. the
  analytic model, and threat-model assumptions vs. the experiments.

Before a live presentation, run `bash scripts/preflight_check.sh` (self-test,
model, tests, ports, data) and see `docs/PRESENTER_GUIDE.md`.

All pages import directly from `crypto/`, `api/`, `bench/`,
`threats/`, and `analysis/` — there is no separate "demo" implementation of
the protocol or the statistics; the dashboard is a thin interactive layer
over the same code the CLI and the paper's results are built from.

## Repository structure

```
pq-shield/
├── crypto/            oqs_adapter (liboqs ctypes), aead, base, registry, instrumentation,
│                      classical / classical_ecdhe / hybrid / hybrid_kex / full_pqc / hybrid_kex_pq,
│                      streaming (signing strategies + checkpoints), handshake_auth
├── api/               server.py (control), server_config_* (one per configuration), secure_app.py,
│                      secure_client.py, secure_streaming_client.py, CLI clients
├── bench/             orchestrator, runner, streaming_runner, netem_proxy, paper_runs
├── threats/           hndl_capture, mitm_harness + mitm_experiment, streaming_mitm_experiment,
│                      streaming_hndl_experiment, streaming_attack_campaign, key_substitution
├── validation/        nist_kat + kat_vectors + vectors/ (trimmed NIST ACVP JSON, fetch.sh),
│                      spec_conformance, primitive_bench, contention_check
├── analysis/          paper_figures (the paper's figures/tables), aggregate, streaming_analysis,
│                      streaming_model_validation, security_validation, legacy figures/tradeoff_matrix
├── model/             train.py, profiles/ (payload shapes), streaming_backends/ (llama.cpp, synthetic)
├── views/             Streamlit pages (home, key_findings, live_demo, benchmark_runner,
│                      results_explorer, threat_lab, validation)
├── webapp/            ui (styling), findings (cached paper data), data_loader, demo_transaction,
│                      server_manager, colors, ai_summary, chart_explainer
├── app.py             Streamlit entry point
├── .streamlit/        config.toml (light and dark themes)
├── paper/             pq_shield_journal.tex/.pdf, figures/, tables/, diagrams/, key_numbers.md,
│                      environment.json, response_to_reviewers.md, CHANGES.md, reference_audit.md
├── results/           summaries and manifests (raw per-request CSVs are gitignored)
├── tests/             205 passing + 4 legacy failures
├── docs/              DESIGN, STREAMING, THREAT_SCENARIOS, RESULTS_DASHBOARD, PRESENTER_GUIDE, diagrams
├── Documents/         ARCHITECTURE, PROJECT_STATUS, design document, research references
├── scripts/           install_oqs.sh, run_webapp.sh, run_threat_experiments.sh, preflight_check.sh
└── Dockerfile
```

## Status

The paper has been through three rounds of external review (see
`paper/response_to_reviewers.md` and `paper/CHANGES.md`) and is being prepared
for IEEE Access. Open items, stated as limitations in the paper: a separate
load-generator host, server-class and multi-host replication, a TLS-native
implementation, packet-level network emulation, larger models and real request
traces, other tokenizers for the HNDL rate, session resumption across streams,
and side-channel analysis.

## Security scope

These wrappers are an application-layer benchmarking harness, not a
replacement for TLS. The default handshake is **unauthenticated** — the paper
shows that key substitution then succeeds against every configuration,
post-quantum or not — so that a fresh exchange per transaction can be
measured. The authenticated variant (`PQ_SHIELD_AUTH_HANDSHAKE=1`, a transcript
signature under a pinned identity key) stops key substitution but does not
model a PKI. In a real deployment, run the API behind authenticated TLS.
