# Streaming Integration — What Was Done

A detailed record of the work that brought token-by-token streaming (SSE)
support into PQ-Shield end-to-end: merged from a separate working copy,
wired into all four Streamlit dashboard pages, run against a real local
LLM, and extended with its own threat scenario. This complements
[`docs/STREAMING.md`](STREAMING.md) (the protocol design and CLI usage
reference) — that file documents *what the streaming feature is and how to
run it*; this one documents *what was built, in what order, what broke
along the way, and how each piece was verified*.

## 1. Merging the feature in (`pq-shield 3/` → this tree)

A separate working copy (`pq-shield 3/`) had independently built the
streaming feature plus a prerequisite payload-profile refactor, while this
tree had independently gained dashboard run-tracking and an AI-summary
feature. The two were merged, then `pq-shield 3/` was deleted.

**Adopted wholesale** (new files, no conflict with this tree):
`crypto/streaming.py` (the three signing strategies), `api/async_bridge.py`,
`api/secure_streaming_client.py`, `bench/streaming_runner.py`,
`analysis/streaming_analysis.py`, `model/profiles/` (the payload-shape
abstraction: `tabular_small`/`image_cnn`/`embedding`/`llm_completion`),
`model/streaming_backends/` (synthetic + optional real llama.cpp/transformers
backends), `validation/` (ML-KEM-768/ML-DSA-65 known-answer-test
conformance), `docs/STREAMING.md`, `docs/PRESENTER_GUIDE.md`,
`docs/diagrams/` (this tree's own `ARCHITECTURE.md` already referenced these
SVGs — they didn't exist here until this merge; a pre-existing broken-link
bug, fixed as a side effect), `scripts/preflight_check.sh`,
`requirements-streaming.txt`, and three new test files
(`test_payload_profiles.py`, `test_streaming_signing.py`,
`test_validation.py`).

**Adopted wholesale, replacing this tree's versions**: `api/schemas.py`,
`api/secure_app.py` (gained `POST /secure/predict/stream`),
`api/secure_client.py`, `api/server.py`, `api/_client_cli.py`,
`api/model_service.py` — these needed the payload-profile refactor
streaming depends on; the pre-merge, hardcoded-digit-classifier versions
couldn't run it.

**Merged by hand** (both copies had independently touched these):
`bench/orchestrator.py` and `bench/runner.py` kept this tree's `run_id` +
`ResourceSampler` work and gained `--payload-profile` plumbing;
`threats/hndl_capture.py` and `threats/mitm_experiment.py` switched from a
hardcoded feature vector to `model.profiles.registry.get_profile()`.

**Left untouched, turned out to already be ahead**:
`webapp/data_loader.py` and `pages/2,3,4` — `pq-shield 3` had never touched
these beyond a shared ancestor, so this tree's run_id/AI-summary work there
was already a strict superset.

**Verified**: full pytest run unchanged at 64 passed / 4 failed (the 4 are
pre-existing failures in unmaintained legacy test files predating
`tests/test_crypto_roundtrip.py` — unrelated to this merge, still present
and still worth cleaning up separately), plus a live `TestClient` smoke test
of a full ML-KEM-768/ML-DSA-65 `/secure/predict` round trip.

## 2. Real model backend setup

The streaming feature works out of the box against a synthetic token
generator (deterministic, zero dependencies). To get genuine LLM timing
numbers, a real backend was set up on this machine (an M3 MacBook Air),
following `docs/STREAMING.md` §5's Option A1:

- Downloaded **`models/Llama-3.2-3B-Instruct-Q4_K_M.gguf`**
  (2,019,377,696 bytes / 2.02 GB, `bartowski/Llama-3.2-3B-Instruct-GGUF`)
  via the `huggingface_hub[cli]` `hf download` command (the older
  `huggingface-cli` is deprecated in the installed version).
- **`llama-cpp-python`'s prebuilt Metal wheel failed** —
  `pip install ... --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/metal`
  raised `zipfile.BadZipFile: Bad CRC-32` twice in a row (not a transient
  network blip — reproduced with `--no-cache-dir` too), most likely no
  matching wheel for this Python (3.13). Fell back to building from source
  with Metal explicitly enabled:
  `CMAKE_ARGS="-DGGML_METAL=on -DCMAKE_OSX_ARCHITECTURES=arm64" pip install --upgrade --force-reinstall --no-cache-dir llama-cpp-python`
  — installed `llama-cpp-python==0.3.35` cleanly.
- **Verified GPU offload actually compiled in** (the docs explicitly warn
  not to assume this): `llama_supports_gpu_offload()` → `True`, correctly
  detecting the M3's Metal GPU (`MTLGPUFamilyApple9`).
- Added `PQ_SHIELD_STREAMING_BACKEND=llama_cpp` and
  `PQ_SHIELD_LLAMA_MODEL_PATH=<repo>/models/Llama-3.2-3B-Instruct-Q4_K_M.gguf`
  to `.env` so every dashboard page and CLI invocation on this machine
  defaults to the real backend.

## 3. First real-model streaming sweep

A scaled-down (18-transaction) real-generation sweep across all three
protected configs × all three signing strategies confirmed the design's
core trade-off with genuine timing rather than synthetic numbers:

| strategy | time-to-first-token | signature bytes (200-tok, full-pqc) |
|---|---|---|
| `buffer_and_sign` | ~16–18s (= whole generation) | 3,309 |
| `hash_chain` | ~140–570ms | 3,309 |
| `per_chunk` | ~330–430ms | 132,360 (40x more, ML-DSA-65 is large) |

All 18/18 transactions succeeded with `stream_fully_verified: True`. Raw
results: `results/streaming/{classical,hybrid,full-pqc}-streaming.csv`;
summarized via `analysis/streaming_analysis.py` into
`results/streaming_summary.csv`.

## 4. Live Demo — streaming panel

`pages/1_🔴_Live_Demo.py` gained a second tab, **"🌊 Streaming Response
(SSE)"**, alongside the existing single-prediction demo:

- Pick a protected config, a signing strategy, a prompt, max tokens, and
  chunk size, then **Start streaming**: tokens appear live as they arrive
  over `/secure/predict/stream`, each chunk shown with its own verification
  badge (signature/chain/AEAD ✅ or ❌) the instant it's checked.
- A **live tamper toggle** corrupts one chosen chunk's ciphertext or
  signature *as it arrives* — the same tamper-injection pattern as the
  single-prediction tab's, extended to a stream, with detection isolated to
  the exact injected chunk.
- New `webapp/demo_transaction.run_streaming_transaction_live()` — an async
  generator mirroring `api/secure_streaming_client.run_streaming_transaction`,
  but yielding one event per chunk (for live UI updates) instead of one
  flat result at the end, plus the tamper-injection hook.
- Reuses the existing demo-server infrastructure (`server_manager`, ports
  8100–8103) unchanged — the same servers already serve
  `/secure/predict/stream`.

**Verified**: the generator was exercised directly against a live full-PQC
server for all 3 strategies, clean and tampered — tamper detection
correctly isolated to the exact injected chunk every time (e.g. `per_chunk`
tamper at index 1 flags only chunk 1; `hash_chain` tamper at index 2
correctly breaks the chain from that point forward, both AEAD and chain
checks). Page executes without exception in a bare-mode script run and
loads live (HTTP 200, clean server logs). *Caveat*: no browser automation
tool was available in this environment, so the widget rendering itself
(vs. the logic behind it) was not visually clicked through.

## 5. Benchmark Runner — streaming sweep tab

`pages/2_🚀_Benchmark_Runner.py` gained a second tab, **"🌊 Streaming
Sweep"**, alongside the existing concurrency sweep — wraps
`bench.streaming_runner.run_sweep` (the CLI tool behind
`docs/STREAMING.md`'s numbers):

- Pick configs, signing strategies, response lengths, and chunk sizes; runs
  one streaming transaction per combination with a live combo count.
- **Backend selector**: Synthetic (default, fast) vs. Real model —
  llama.cpp, with an availability check (`llama_cpp` importable +
  `PQ_SHIELD_LLAMA_MODEL_PATH` pointing at a real file) that auto-falls-back
  to synthetic with an error if real is picked but not actually set up.
  Synthetic mode exposes a tokens/sec slider (default 300, faster than the
  CLI's realism-focused default of 30) since this is for quick interactive
  checks. A warning fires above 20 combos on the real backend, since each
  is genuine generation.
- New `webapp/data_loader.streaming_file_inventory()` /
  `load_streaming_df()` — mirror the existing `raw_file_inventory()`
  pattern for `results/streaming/*.csv`.

**Verified**: directly called the exact `run_sweep` path the page uses —
servers started/stopped cleanly, all transactions verified. Page executes
without exception (bare-mode run) and loads live (HTTP 200).

## 6. Results Dashboard — streaming section

`pages/3_📊_Results_Dashboard.py` gained a **"🌊 Streaming Response
Overhead"** section (between Server Resource Usage and Aggregate
Statistics), reading from `results/streaming/*.csv` — a separate data
source from the concurrency-sweep sections above it, not scoped by the
run_id selector:

- Metrics row (transaction count, errors, all-verified badge), a
  response-length + chunk-size selector, and two side-by-side charts: TTFT
  by strategy (grouped bars per config) and signature-byte overhead by
  strategy (log-scale, since `per_chunk` on full-pqc is ~40x the others).
- A strategy-comparison table per config (speedup vs. `buffer_and_sign`,
  byte-reduction vs. `per_chunk`) straight from
  `analysis.streaming_analysis.strategy_comparison_at` — the same function
  the CLI's headline numbers come from, not a reimplementation.
- Graceful empty state pointing at the Benchmark Runner's Streaming Sweep
  tab if no data exists yet.

**Verified**: ran the exact `streaming_analysis.summarize()` /
`strategy_comparison_at()` calls against the real Llama-3.2-3B sweep data —
confirmed `hash_chain` gets ~47–52x the TTFT speedup of `buffer_and_sign`
at 97.5% fewer signature bytes than `per_chunk`. This page has no
button-gating, so the bare-mode execution test exercised the entire new
section end-to-end with real data, not just import-checked it.

## 7. Bug fix: `.env` quote parsing broke the AI Summary button

**Symptom reported**: `AI summary failed: Error code: 401 - ... 'invalid
x-api-key'`.

**Root cause**: `webapp/bootstrap.py`'s `load_dotenv_if_needed()` (called at
the top of every dashboard page) did `val.strip()` on each `.env` line's
value — which trims whitespace but *not* surrounding quote characters. This
repo's `.env` has `ANTHROPIC_API_KEY="sk-ant-..."` (quoted); the parser was
setting the environment variable to the literal string `"sk-ant-...="`
— quote characters included — whenever this Python-side parser was the one
actually setting it (i.e. any launch path that doesn't first go through
`scripts/run_webapp.sh`'s shell-level `export $(... | xargs)`, which
happens to dequote correctly on its own via `xargs`'s word-splitting).

**Fix**: `bootstrap.py` now strips one matching pair of surrounding quotes
— the standard `.env` convention (same as `python-dotenv`).

**Verified the underlying key was never the problem**: with the corrected
parsing, a real minimal call to the Anthropic API (`claude-haiku-4-5`, 1
token) succeeded.

## 8. Threat Scenarios — streaming sequence-integrity attack

The initial pass on this page was left as-is, on the reasoning that
byte-corruption (the existing MITM tab) is caught immediately by AES-GCM in
every streaming strategy and isn't differentiated by strategy — re-running
it wouldn't teach anything new. On reflection there **is** a genuine,
strategy-differentiated streaming threat: a **sequence-integrity attack** —
silently dropping or reordering one chunk, without touching any chunk's own
bytes. `per_chunk` signs each chunk's position and catches this on the very
next chunk; `hash_chain` deliberately defers its sequence guarantee to the
*terminating* signature (to amortize signing cost across the stream), so
the attack is invisible to the client until the entire (possibly forged)
response has already arrived — and in a real chat UI, likely already been
shown to the user.

**New**: `threats/streaming_mitm_experiment.py` — `run_trial()` collects one
real streaming response in full, mutates the middle of its chunk sequence
(drop or swap-adjacent), then replays the mutated sequence through the same
client-side verification functions (`crypto/streaming.verify_per_chunk` /
`verify_hash_chain_chunk` / `verify_hash_chain_final`) a real client runs
incrementally, tracking the exact position where the tamper is first
flagged (if ever). `summarize()` aggregates trials into `detection_rate`,
`mid_stream_detection_rate`, and `fraction_delivered_before_detection_mean`.
A CLI entrypoint (`python -m threats.streaming_mitm_experiment`) mirrors the
other threat scripts' start-server-per-config pattern.

**Two real bugs found and fixed while building/testing this** (both would
have silently produced wrong data if shipped):

1. **SSE trailer confused for the final signed event.** The stream's
   trailing `event: done\ndata: {...}` line (no `"kind"` field) was being
   caught by an `else: final_event = data` catch-all and overwriting the
   real `final_chain` event that arrived just before it — `hash_chain`
   looked completely undetectable (`detection_rate: 0.0`) until fixed by
   only accepting `kind in ("final_buffered", "final_chain")`.
2. **Hyphenated config key passed where a crypto name was needed.** The
   CLI's `main()` passed `"full-pqc"` (the `SERVER_MODULES` key) straight
   into `run_experiment`, which needs `"full_pqc"` (what
   `crypto.registry.get_client_crypto` expects) — crashed with `KeyError`
   on the third config (worked for `classical`/`hybrid` by coincidence,
   since those two are spelled identically in both forms). Fixed by mapping
   through `CONFIG_TO_CRYPTO_NAME` before calling `run_experiment`, matching
   `bench/streaming_runner.py`'s existing pattern.

**Results** (real run, all 3 protected configs, 10 trials per combination,
synthetic backend, `results/streaming/mitm/*.json`):

| strategy | detection rate | mid-stream detection | % of response delivered before caught |
|---|---|---|---|
| `per_chunk` | 100% | 100% | ~50–55% (right at the tampered position) |
| `hash_chain` | 100% (eventually) | **0%** | **100%** — the whole response arrives first |
| `buffer_and_sign` | n/a | n/a | delivers nothing incrementally; attack doesn't apply |

This is `hash_chain`'s documented signature-byte trade-off made concrete,
not a defect — flagged as such (vs. a real problem) explicitly in the
AI-summary prompt below.

**Wired in**: a new "🌊 Streaming Sequence Attack" tab on
`pages/4_🛡️_Threat_Scenarios.py` (existing-results charts + a live
run-it-yourself button, matching the HNDL/MITM tabs' pattern), new
`webapp/data_loader.load_streaming_mitm_summaries()` (kept in its own
directory/loader — `results/streaming/mitm/`, distinct from
`results/mitm/`'s glob — rather than folded into `load_mitm_summaries()`,
since the two summary shapes differ and mixing them would produce a
confusing combined table). `webapp/ai_summary.build_threat_context()` and
its system prompt were extended to describe this third data source,
including explicit guidance not to treat `hash_chain`'s by-design
mid-stream blind spot as a security failure unless `detection_rate` itself
(not `mid_stream_detection_rate`) drops below 100%.

## 9. Verification approach used throughout

No browser automation tool was available in this environment, so "did it
actually work" was established through several complementary layers rather
than a single method, applied to every change above:

1. **Syntax check** (`ast.parse`) on every edited page/module.
2. **Direct functional test** of the underlying logic against a real,
   locally-running protected server (not mocked) — e.g. calling
   `run_streaming_transaction_live` / `run_trial` / `run_sweep` directly and
   inspecting results, including deliberately-tampered cases.
3. **Bare-mode script execution** (`runpy.run_path`) of each Streamlit page
   — catches import errors, undefined names, and wrong call signatures that
   `ast.parse` can't; for pages without button-gating (Results Dashboard,
   Threat Scenarios' top sections) this exercises real chart-building code
   against real data on disk, not just imports.
4. **Live dashboard launch** (`bash scripts/run_webapp.sh` on a scratch
   port) + `curl` against both the home page and the specific page's direct
   URL, checking for HTTP 200 and a clean server log.
5. **Full `pytest -q` run** after every change, confirming the count stayed
   at 64 passed / 4 pre-existing failures (never a new failure introduced).
6. Background/long-running steps (the 2GB model download, the source
   build, real-generation sweeps) were run detached and polled rather than
   blocking, with explicit process cleanup (`kill`) and a `ps aux` check
   afterward to confirm nothing was left running beyond what predated the
   change.

## 10. Current state on disk

```
models/Llama-3.2-3B-Instruct-Q4_K_M.gguf   # 2.02 GB, real backend model
results/streaming/*.csv                     # bench.streaming_runner sweep (real model, 18 rows)
results/streaming_summary.csv               # analysis.streaming_analysis output
results/streaming/mitm/*.json               # threats.streaming_mitm_experiment (synthetic backend, 15 files)
.env                                        # + PQ_SHIELD_STREAMING_BACKEND, PQ_SHIELD_LLAMA_MODEL_PATH
```

Full list of files touched by this integration (merge + dashboard work +
threat scenario + bugfixes): see `git status` — every core module under
`api/`, `bench/`, `crypto/`, `webapp/`, `pages/`, plus the new
`threats/streaming_mitm_experiment.py`, `analysis/streaming_analysis.py`,
`model/profiles/`, `model/streaming_backends/`, `validation/`, and
`docs/{STREAMING,PRESENTER_GUIDE,STREAMING_INTEGRATION}.md`.

## 11. What's not done yet

- Nothing has been committed — all of the above is uncommitted working-tree
  state (see `git status`). `PROJECT_STATUS.md` §"Known gaps" already flags
  this and recommends cleaning up the 4 pre-existing legacy test failures
  before committing.
- The Live Demo streaming panel's widget *rendering* (vs. the logic behind
  it) hasn't been visually clicked through in a real browser — worth a
  quick look via `bash scripts/run_webapp.sh` before considering it fully
  done.
- Only a scaled-down real-model sweep has been run (§3); the full
  documented sweep (3 lengths × 3 chunk sizes × 3 reps = 54 real-generation
  transactions) would take considerably longer but give paper-ready
  statistics rather than a first look.
- The streaming sequence-attack experiment (§8) has only been run against
  the synthetic backend; re-running it against the real Llama-3.2-3B
  backend would confirm the same detection-latency finding holds under
  genuine generation timing, not just simulated.
