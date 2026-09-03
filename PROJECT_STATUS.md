# PQ-Shield — Project Status

A snapshot of what exists in this repository and what it does, as of
**2026-09-01** on branch `local-sync`. For setup/usage see
[README.md](README.md); for module-by-module structure and data flow see
[ARCHITECTURE.md](ARCHITECTURE.md) and [docs/DESIGN.md](docs/DESIGN.md); for
a detailed, chronological record of the streaming-feature integration
(merge, real-model setup, all four dashboard pages, a bug fix, a new threat
scenario, and how each piece was verified) see
[docs/STREAMING_INTEGRATION.md](docs/STREAMING_INTEGRATION.md) — this file
summarizes the end state, that one documents how it got there.
`PROJECT_STRUCTURE.md` predates all of these and describes an earlier
layout (`config_a_classical.py`, `oqs_kem.py`, `work/oqs-prefix/`, only two
protected configs) — treat this file and `ARCHITECTURE.md` as current, not it.

## What the project is

An empirical benchmark of the cost of migrating a real-time AI inference API
to NIST post-quantum cryptography. The same FastAPI digit-classifier
inference workload runs behind four crypto configurations — an unprotected
control, and three protected configs (classical RSA/ECDSA, hybrid
ML-KEM-768+ECDSA, full PQC ML-KEM-768+ML-DSA-65) — and is subjected to
concurrency sweeps plus two threat experiments (harvest-now-decrypt-later,
active MITM tampering), producing a weighted security/performance
trade-off matrix.

## Repository inventory

| Area | Contents | Status |
|---|---|---|
| `crypto/` | `oqs_adapter.py` (ctypes binding to a locally-built liboqs, ML-KEM-768 + ML-DSA-65), `base.py` (shared config interface), `classical.py`/`hybrid.py`/`full_pqc.py` (the three protected configs), `aead.py` (shared AES-256-GCM + HKDF), `registry.py`, `instrumentation.py` (`Timer`, `ResourceSampler`) | Implemented |
| `api/` | Control server + 3 protected servers (`server*.py`), shared handshake/predict logic (`secure_app.py`), shared inference call (`model_service.py`), per-config CLI clients + shared async client (`secure_client.py`) | Implemented |
| `model/` | `train.py` trains a 100-tree RandomForest on sklearn's `load_digits` (1,797 samples, 64 features, ~96% accuracy); `artifacts/model.pkl` is the trained, checked-in artifact | Implemented |
| `bench/` | `runner.py` (single-cell async load generator, `--server-pid` CPU/RSS sampling), `orchestrator.py` (full concurrency × repetition × config matrix), `streaming_runner.py` (streaming signing-strategy sweep), `metrics.py` (unused legacy) | Implemented |
| `threats/` | `hndl_capture.py`, `mitm_harness.py` + `mitm_experiment.py` (single-shot tamper detection), `streaming_mitm_experiment.py` (streaming sequence-integrity attack — drop/reorder mid-stream) | Implemented |
| `analysis/` | `aggregate.py` (stats + Mann-Whitney U vs. control), `tradeoff_matrix.py` (weighted composite score at 3 weightings), `figures.py` (paper figure set), `plot_metrics.py` (smoke-test chart), `streaming_analysis.py` (TTFT/signature-byte summary + strategy comparison) | Implemented; CPU/RSS heatmap in `figures.py` is still a no-op placeholder |
| `webapp/` + `pages/` + `app.py` | 4-page Streamlit dashboard (Live Demo, Benchmark Runner, Results Dashboard, Threat Scenarios), each with a streaming-specific tab/section; `ai_summary.py` (on-demand Claude summaries) | Implemented — see [docs/STREAMING_INTEGRATION.md](docs/STREAMING_INTEGRATION.md) §4–8 |
| `model/profiles/`, `model/streaming_backends/`, `validation/` | Pluggable payload-shape abstraction, synthetic + real (llama.cpp/transformers) token backends, ML-KEM-768/ML-DSA-65 known-answer-test conformance | Implemented |
| `tests/` | `test_crypto_roundtrip.py` — 13 parametrized round-trip/tamper-detection tests across all 3 configs (current, canonical suite) | 13/13 passing |
| `tests/` (legacy) | `test_classical_roundtrip.py`, `test_hybrid_kem.py`, `test_hybrid_roundtrip.py`, `test_full_pqc.py` — earlier per-config tests predating `test_crypto_roundtrip.py` | 4 of these fail against the current API response schema (`KeyError: 'kem_...'` etc.) — dead/stale, not part of the maintained suite; worth deleting or fixing so `pytest -q` is clean |
| `scripts/` | `install_oqs.sh` (minimal liboqs build), `run_webapp.sh`, `run_threat_experiments.sh` | Implemented |
| `results/` | `raw/` (per-cell CSVs), `hndl/`, `mitm/`, `aggregate_stats.csv`, `sweep_summaries/` (new — see below) | Populated from real runs on this host |
| `outputs/` | Generated figures (`fig1`–`fig3`, `fig6` currently present as PNGs) | Populated |
| `Dockerfile` | Builds liboqs, installs deps, trains the model, runs self-test + full pytest at image-build time | Implemented |
| `liboqs/`, `oqs-prefix/` | Vendored/built third-party PQC library, not project code | Present (build output) |

Full pytest run right now: **17 passed, 4 failed** (21 collected) — the 13
canonical tests plus 4 legacy per-config tests fail as noted above; the
failures are pre-existing schema drift in unmaintained test files, not a
regression from the current uncommitted changes.

## Streaming integration (this pass)

Full details, in order, with what broke and how each step was verified:
**[docs/STREAMING_INTEGRATION.md](docs/STREAMING_INTEGRATION.md)**. Summary:

1. Merged the streaming feature (and its prerequisite payload-profile
   refactor) in from a separate working copy, `pq-shield 3/`, then deleted
   that folder — this tree's independent run_id/AI-summary dashboard work
   was preserved throughout (it turned out to already be a strict superset
   in the files that mattered).
2. Set up a real local LLM backend (Llama-3.2-3B-Instruct, Q4_K_M GGUF, via
   `llama-cpp-python` built from source with Metal on this M3 Air — the
   prebuilt wheel failed a CRC check) and ran a first real-generation sweep.
3. Added a live SSE streaming panel to the **Live Demo** page (token-by-token
   display, per-chunk verification badges, live tamper injection).
4. Added a **Streaming Sweep** tab to the **Benchmark Runner** page
   (synthetic/real backend selector).
5. Added a **Streaming Response Overhead** section to the **Results
   Dashboard** (TTFT + signature-byte charts, strategy-comparison table).
6. Fixed a real bug: `webapp/bootstrap.py`'s `.env` parser wasn't stripping
   quote characters, which broke the AI Summary button with a 401
   (`ANTHROPIC_API_KEY` was being set to `"sk-ant-..."` literally, quotes
   included) whenever the app was launched without going through
   `scripts/run_webapp.sh`'s shell-level export.
7. Added a genuinely new threat scenario — `threats/streaming_mitm_experiment.py`
   measures **sequence-integrity attacks** (drop/reorder a chunk mid-stream,
   as opposed to byte corruption, which AES-GCM already catches immediately
   in every strategy) and found `hash_chain` never catches these until the
   stream has fully arrived (a documented trade-off, not a defect) — wired
   into a new **Streaming Sequence Attack** tab on the Threat Scenarios
   page. Two real bugs were caught and fixed while building it (an SSE
   trailer being mistaken for the final signed event, and a hyphenated
   config key reaching a function that needed the underscored crypto name).

Verified after every step: full pytest run stayed at **64 passed / 4
failed** (the pre-existing legacy-test failures noted above — never a new
regression), plus direct functional tests against real running servers,
bare-mode Streamlit script execution, and live dashboard launches with
`curl` checks (see the integration doc §9 for the full methodology).

`README.md` and `ARCHITECTURE.md` were updated with sections covering
payload profiles, streaming, and `validation/`, but do **not** yet describe
the dashboard-side work (items 3–7 above) or the run_id/AI-summary
dashboard features from before this pass — worth a pass once this is ready
to commit.

## Uncommitted work on this branch (`git status`)

Nothing above has been committed yet — everything in this section and the
integration doc is current working-tree state. Beyond what's covered above:
per-run tracking in the dashboard (`run_id`, `results/sweep_summaries/*.json`,
a run selector on the Results Dashboard/Benchmark Runner pages, with rows
lacking `run_id` bucketed under an explicit "legacy" label rather than
silently dropped) and new MITM signature-tamper results
(`results/mitm/{full_pqc,hybrid}-mitm-{ciphertext,signature}-summary.json`)
both predate this pass and are still uncommitted; `ARCHITECTURE.md` itself
is new/untracked.

## Known gaps / next steps

Carried over from `README.md`'s "Current status / next steps", still open:

1. Re-run the full benchmark matrix on multi-core, non-sandboxed hardware —
   current absolute latency numbers were produced on a single-core sandbox.
2. Add the CIFAR-10 CNN sensitivity workload (larger payloads) from the
   Review 1 proposal, to test whether findings generalize beyond the
   64-feature digit model.
3. Wire CPU/RSS resource sampling through the full-matrix
   `bench/orchestrator.py` path (it's currently only available in
   `bench/runner.py`'s single-cell `--server-pid` mode); `analysis/figures.py`'s
   CPU/RSS heatmap is a no-op placeholder until this lands.
4. Push the `--reuse-handshake` "warm connection" variant through the full
   sweep as a secondary result (`docs/DESIGN.md` §4.2/§3).
5. Publish per the Review 1 proposal's target venue and tag a release for
   the open-source artifact.

New, from this pass:

6. Clean up or delete the 4 failing legacy test files (`tests/test_classical_roundtrip.py`,
   `tests/test_hybrid_kem.py`'s sibling `test_hybrid_roundtrip.py`, `tests/test_full_pqc.py`)
   so `pytest -q` is fully green — they predate and duplicate
   `tests/test_crypto_roundtrip.py` and now fail against the current schema.
7. Commit or clean up the in-flight dashboard work above (run tracking, AI
   summary, new MITM signature results) and update `README.md`/`ARCHITECTURE.md`
   to describe it once committed.
8. Refresh or remove the stale `PROJECT_STRUCTURE.md`, which still describes
   a pre-full-PQC, pre-`work/`-reorg layout.

From the streaming integration pass — see
[docs/STREAMING_INTEGRATION.md](docs/STREAMING_INTEGRATION.md) §11 for
detail:

9. Visually click through the Live Demo streaming panel in a real browser —
   its logic is verified, its rendering isn't (no browser automation tool
   was available in this environment).
10. Run the full documented streaming sweep (3 lengths × 3 chunk sizes ×
    3 reps = 54 real-generation transactions) rather than the scaled-down
    first-look sweep currently on disk.
11. Re-run `threats/streaming_mitm_experiment.py` against the real
    Llama-3.2-3B backend (currently only run against synthetic) to confirm
    the detection-latency finding holds under genuine generation timing.
