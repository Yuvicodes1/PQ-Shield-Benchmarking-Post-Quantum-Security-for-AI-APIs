# Streaming Signatures — What This Adds and Why

This document covers a new capability added to PQ-Shield: benchmarking
cryptographic signature overhead for **streaming** AI API responses (the
token-by-token SSE pattern every real LLM chat API uses), as opposed to the
single-shot JSON responses the rest of this project measures.

Read this top to bottom once; after that, use it as a reference for the file
manifest and command list further down.

---

## 1. Why this needed to exist

Every crypto configuration elsewhere in this project signs one complete
response in one call — correct for a classifier's single JSON reply, but
impossible for a token-by-token LLM stream, because **you cannot sign a
response you have not finished generating yet.**

Using PQ-Shield's own measured primitive costs (`results/validation/primitive_bench.json`),
the full-PQC crypto cost of one non-streaming transaction is about 241 µs.
Against a multi-second LLM generation, that overhead all but disappears —
which would have made a real-model experiment here anticlimactic. Streaming
reframes the question entirely: if you sign **every** chunk of a streamed
response, the signature overhead scales with the *number of chunks*, not the
crypto configuration, and it can become enormous. That's a genuinely new,
quantifiable, AI-API-specific research question this project's existing
framework was well-positioned to answer.

## 2. The three strategies

You cannot sign a response you have not finished generating. Three answers:

| Strategy | What it does | Time-to-first-token | Signature bytes |
|---|---|---|---|
| `buffer_and_sign` | Wait for the whole response, sign once | **Worst** — equals total generation time; streaming is defeated | **Best** — exactly 1 signature |
| `per_chunk` | Sign every chunk independently, the instant it's generated | **Best** — first chunk ships immediately | **Worst** — N signatures for N chunks |
| `hash_chain` | Encrypt every chunk immediately (AEAD authenticates it right away); fold each into a running SHA-256 hash chain; sign only the final hash | **Best** — same as per_chunk | **Best** — same as buffer_and_sign (1 signature, or 1 per checkpoint) |

`hash_chain` is the interesting result: it gets the good time-to-first-token
of `per_chunk` **and** the low signature overhead of `buffer_and_sign`. The
cost is that the "this is the complete, correctly-ordered stream" guarantee
is only confirmed once the terminating signature arrives — individual chunk
tampering is still caught immediately via AEAD, just not the *sequence*
guarantee (nothing dropped, nothing reordered).

**Real numbers from this project's own test sweep** (Full PQC config,
100-token response, one token per chunk — see `results/streaming/` after you
run the sweep yourself):

| Strategy | Time-to-first-token | Total signature bytes |
|---|---|---|
| `buffer_and_sign` | 67.5 ms | 3,309 B |
| `per_chunk` | 2.3 ms (**29.6× faster**) | 330,900 B (**100 signatures**) |
| `hash_chain` | 2.1 ms (**32.7× faster**) | 3,309 B (**same as buffer_and_sign**) |

### A security subtlety worth knowing (and worth citing)

A naive `per_chunk` implementation that signs only `nonce || ciphertext` per
chunk is vulnerable to **reordering**: every individual chunk's signature
still verifies correctly even if an active adversary swaps two chunks in
transit, because no chunk's signature says anything about its position in
the sequence. This implementation closes that by binding the chunk index
into what gets signed (`index || nonce || ciphertext`) and having the client
independently track an expected sequence counter. `hash_chain` is not
vulnerable to this in the first place — each link folds in the previous
link's hash, so reordering or dropping any chunk changes every subsequent
hash, which the terminating signature catches deterministically. See
`crypto/streaming.py`'s module docstring and
`tests/test_streaming_signing.py::test_per_chunk_detects_reordering` /
`::test_hash_chain_detects_dropped_chunk`.

## 3. Real model vs. synthetic — be precise about which is which

Three interchangeable **generation backends** (`model/streaming_backends/`)
produce the token stream. Only one is real by default:

| Backend | `real_inference` | Dependencies | Where it runs |
|---|---|---|---|
| `synthetic` (default) | `False` | none | anywhere, including this project's own sandboxed dev environment |
| `llama_cpp` | `True` | `llama-cpp-python` + a local GGUF file | your machine |
| `transformers` | `True` | `transformers` + `torch` + a model | your machine |

The synthetic backend is not a placeholder to be embarrassed about — it's
what let the crypto/protocol layer (the actual contribution) be built and
tested rigorously (28 passing tests) in an environment with no GPU and no
internet access to model hosts. But **the crypto findings above hold
regardless of backend**, because signature cost depends only on chunk count
and size, not on how the chunk content was produced. Running a real model
changes the *generation* timing (useful for a realistic time-to-first-token
number against real decode speed) but does not change the *signature*
finding.

State this distinction explicitly in the paper, exactly as
`docs/DESIGN.md` already does for the non-streaming `embedding` and
`llm_completion` payload profiles.

---

## 4. File manifest — what to put where

Everything below is a path **relative to your PQ-Shield repository root**.
Files marked **(new)** are new files to add; files marked **(edit)** are
changes to files that already exist in your repo — the instructions tell you
what changed.

### Core crypto (new)

| File | Purpose |
|---|---|
| `crypto/streaming.py` | The three signing strategies (server-side) and matching verifiers (client-side). Read its module docstring first — it explains the reordering-vulnerability fix in detail. |
| `tests/test_streaming_signing.py` | 28 tests: round-trips, tampered-chunk detection, reordering detection, dropped-chunk detection, checkpoint intervals, and a signature-byte-cost sanity check. Run `pytest tests/test_streaming_signing.py -v`. |

### Generation backends (new)

| File | Purpose |
|---|---|
| `model/streaming_backends/__init__.py` | Empty package marker. |
| `model/streaming_backends/base.py` | Abstract `StreamingBackend` interface. |
| `model/streaming_backends/synthetic_backend.py` | Zero-dependency backend. Works immediately, no setup. |
| `model/streaming_backends/llama_cpp_backend.py` | Real backend via llama.cpp. Needs setup — see §5 below. |
| `model/streaming_backends/transformers_backend.py` | Real backend via Hugging Face transformers. Needs setup — see §5 below. |
| `model/streaming_backends/registry.py` | Picks and caches the active backend via the `PQ_SHIELD_STREAMING_BACKEND` env var. |

### API layer

| File | Purpose |
|---|---|
| `api/async_bridge.py` **(new)** | Bridges a blocking sync generator (llama.cpp/transformers are both sync) into an async SSE stream without freezing the server's event loop. |
| `api/secure_app.py` **(edit)** | Adds one new endpoint, `POST /secure/predict/stream`, alongside the existing `/secure/handshake` and `/secure/predict`. If you're merging this into an existing checkout: replace your copy with the one provided — the diff is (a) three new imports (`json` promoted to a top-level import, `StreamingResponse`, `aiter_sync_generator`, `get_server_strategy`, `get_backend`) and (b) one new `@app.post("/secure/predict/stream")` route appended before the final `return app`. Nothing in the existing `/secure/predict` route changed except that a stray local `import json` was removed (it's now a top-level import, used by both routes). |
| `api/secure_streaming_client.py` **(new)** | Client-side: performs the handshake, POSTs to the streaming endpoint, consumes the SSE response, and applies the verification logic matching whichever strategy was requested. Returns one metrics dict per transaction — this is what feeds the CSV rows below. |

### Benchmark and analysis (new)

| File | Purpose |
|---|---|
| `bench/streaming_runner.py` | CLI sweep across configs × strategies × response-length × chunk-size. Starts/stops each config's server itself, exactly like `bench/orchestrator.py`. Writes `results/streaming/{config}-streaming.csv`. |
| `analysis/streaming_analysis.py` | Aggregates those CSVs into a summary table, plus a specific side-by-side strategy comparison at any (config, response length, chunk size) you choose — this is what produced the table in §2 above. |

### Dependencies and docs

| File | Purpose |
|---|---|
| `requirements-streaming.txt` **(new)** | Optional extra dependencies for the two real backends. The core project's `requirements.txt` needs no changes — the synthetic backend has zero extra dependencies. |
| `docs/STREAMING.md` **(new)** | This file. |
| `README.md` **(edit)** | Add one short section linking here — see the exact text to add in §7 below. |

---

## 5. Setting up a real model backend (optional)

Skip this section entirely if you're happy benchmarking the crypto layer
against the synthetic backend — it needs no setup and the signature-byte
findings do not depend on which backend produced the text.

**Important:** a bare `pip install llama-cpp-python` compiles **CPU-only**
on every platform, silently — it does not error, it just won't use your
GPU. GPU acceleration (Metal or CUDA) requires an explicit build flag at
install time. This project's `llama_cpp_backend.py` defaults
`n_gpu_layers=-1` (offload everything), but that setting only does anything
if the underlying build actually has GPU support compiled in — so verify it
worked (command at the end of this section), don't just assume it.

### Recommended model (same file for both machines below)

**`Llama-3.2-3B-Instruct-Q4_K_M.gguf`** (2.02 GB) — small enough to load
almost instantly, good enough quality to give realistic decode-speed
timing, and using the *identical file* on both an Apple Silicon machine and
a CUDA machine lets you directly compare Metal vs. CUDA decode speed with
model weights held constant.

```bash
pip install -U "huggingface_hub[cli]"
huggingface-cli download bartowski/Llama-3.2-3B-Instruct-GGUF \
  --include "Llama-3.2-3B-Instruct-Q4_K_M.gguf" --local-dir ./models
```

### Option A1 — llama.cpp on Apple Silicon (M-series Mac, e.g. your M3 Air)

Prebuilt Metal wheels exist and are the fastest path — try this first:

```bash
pip install llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/metal
```

If that wheel doesn't match your Python version, fall back to building from
source with Metal explicitly enabled (a few minutes, needs Xcode command
line tools):

```bash
CMAKE_ARGS="-DGGML_METAL=on -DCMAKE_OSX_ARCHITECTURES=arm64" \
  pip install --upgrade --force-reinstall --no-cache-dir llama-cpp-python
```

```bash
export PQ_SHIELD_STREAMING_BACKEND=llama_cpp
export PQ_SHIELD_LLAMA_MODEL_PATH=$(pwd)/models/Llama-3.2-3B-Instruct-Q4_K_M.gguf
```

### Option A2 — llama.cpp on your CUDA laptop

Requires the CUDA Toolkit already installed (`nvcc --version` must work).
There is no CPU-only fallback here — this always compiles from source with
the CUDA backend explicitly enabled:

```bash
CMAKE_ARGS="-DGGML_CUDA=on" pip install --upgrade --force-reinstall --no-cache-dir llama-cpp-python
```

```bash
export PQ_SHIELD_STREAMING_BACKEND=llama_cpp
export PQ_SHIELD_LLAMA_MODEL_PATH=/path/to/models/Llama-3.2-3B-Instruct-Q4_K_M.gguf
```

If you have a large amount of VRAM (12GB+) and want a more
production-realistic model size, `bartowski/Meta-Llama-3.1-8B-Instruct-GGUF`
(Q4_K_M, ~4.9 GB) is a reasonable step up — same download pattern, larger
`--include` filename.

### Verifying GPU offload actually happened (do this on both machines)

```bash
python -c "
from llama_cpp import llama_supports_gpu_offload
print('GPU offload compiled in:', llama_supports_gpu_offload())
"
```

If this prints `False`, the install compiled CPU-only regardless of what
`PQ_SHIELD_LLAMA_GPU_LAYERS` is set to — re-run the install command for your
platform above with `--force-reinstall --no-cache-dir` (pip will otherwise
reuse a cached CPU-only wheel and silently ignore the new `CMAKE_ARGS`).

### Option B — Hugging Face transformers

```bash
pip install -r requirements-streaming.txt   # installs transformers + torch

export PQ_SHIELD_STREAMING_BACKEND=transformers
export PQ_SHIELD_HF_MODEL=meta-llama/Llama-3.2-1B-Instruct   # downloads on first use
# or point at a local model directory you already have:
# export PQ_SHIELD_HF_MODEL=/path/to/local/model/dir

# If you have a CUDA GPU:
export PQ_SHIELD_HF_DEVICE=cuda
# On Apple Silicon, transformers uses MPS, generally slower than llama.cpp's
# Metal path for a quantized GGUF model -- prefer Option A1 above on a Mac.
```

Hub downloads require ordinary internet access to huggingface.co — this
project's own development sandbox has that host blocked, which is exactly
why both real backends are designed to be installed and run on your
machine, not the environment that built them.

### Verifying a real backend works

```bash
python -c "
from model.streaming_backends.registry import get_backend
b = get_backend()
print('backend:', b.name, '| real_inference:', b.real_inference)
for piece in b.stream('Say hello in one short sentence.', max_tokens=20):
    print(piece, end='', flush=True)
print()
"
```

---

## 6. Running it

### Quick manual check (synthetic backend, no setup)

```bash
export PQ_SHIELD_OQS_LIB=<repo>/oqs-prefix/lib/liboqs.so   # as usual
export PQ_SHIELD_SYNTHETIC_TOKENS_PER_SEC=500                # faster than default 30, for a quick check

uvicorn api.server_config_c:app --port 8000 &

python -c "
import asyncio, httpx
from api.secure_streaming_client import run_streaming_transaction

async def main():
    async with httpx.AsyncClient(timeout=30.0) as client:
        for strategy in ['buffer_and_sign', 'per_chunk', 'hash_chain']:
            m = await run_streaming_transaction(
                client, 'http://127.0.0.1:8000', 'full_pqc',
                prompt='test prompt', strategy=strategy,
                chunk_size_tokens=5, max_tokens=30,
            )
            print(strategy, '-> ttft_ms:', m['ttft_ms'], '| signature bytes:', m['total_signature_bytes'])

asyncio.run(main())
"
```

### Full benchmark sweep

```bash
# For a quick, correctness-focused sweep, keep the synthetic backend fast:
export PQ_SHIELD_SYNTHETIC_TOKENS_PER_SEC=1000

python -m bench.streaming_runner \
  --configs classical,hybrid,full-pqc \
  --strategies buffer_and_sign,per_chunk,hash_chain \
  --max-tokens 50,200,500 \
  --chunk-size-tokens 1,5,20 \
  --repetitions 3
```

This starts each config's server itself, one at a time, exactly like
`bench/orchestrator.py`'s main sweep. With the parameters above (3 configs ×
3 strategies × 3 lengths × 3 chunk sizes × 3 reps = 243 transactions), it
runs in well under a minute against the synthetic backend at 1000 tok/s. If
you're using a real backend, budget real generation time per transaction —
243 transactions at even 2 seconds each is 8+ minutes.

### Analyze results

```bash
python -m analysis.streaming_analysis \
  --streaming-dir results/streaming \
  --output results/streaming_summary.csv \
  --highlight-config full_pqc \
  --highlight-max-tokens 500 \
  --highlight-chunk-size 1
```

The `--highlight-*` flags print the specific side-by-side strategy
comparison table (the one in §2 above) for whichever (config, response
length, chunk size) combination you want to feature.

---

## 7. Add this pointer to your `README.md`

Add this section to your existing `README.md` (e.g. right after the
"Interactive dashboard" section):

```markdown
## Streaming signatures (LLM-style token streams)

The above benchmarks single-shot JSON responses. For token-by-token SSE
streaming responses -- the shape a real chat-completion API actually
uses -- see `docs/STREAMING.md`, which covers three signing strategies
(buffer-and-sign, per-chunk, hash-chain), their time-to-first-token and
signature-byte-overhead trade-offs, and how to run the real vs. synthetic
generation backends.
```

---

## 8. Relationship to the main benchmark

`bench/streaming_runner.py` is deliberately a **separate, low-concurrency**
sweep, not folded into `bench/orchestrator.py`'s concurrency matrix. The
variable under study here is response length and signing strategy; the
variable under study in the main sweep is concurrent load. Combining both
in one experiment would confound "is this slow because of concurrency
contention or because of the signing strategy?" — exactly the kind of
confound `docs/DESIGN.md` already goes out of its way to avoid elsewhere
(e.g. keeping AES-256-GCM identical across all three crypto configs so only
the asymmetric primitive varies). If you want streaming under concurrent
load as a follow-up experiment, run multiple `run_streaming_transaction`
calls concurrently via `asyncio.gather` in a small driver script, but
report it as a separate result with its own caveats, not blended into
either existing sweep.

## 9. Validating the measurement instrument itself

There is no published external dataset measuring PQC signature overhead on
*streamed* AI responses. That absence is this project's own novelty claim —
if such a dataset existed, this work would be redundant. So "validate
against an external ground truth," the approach `validation/nist_kat.py`
takes for the raw primitives (byte-exact match against NIST's own ACVP
known-answer vectors), is not achievable for the streaming result the same
way.

What is validated instead is the **measurement instrument itself**. The
signing strategies in `crypto/streaming.py` implement pure, deterministic
arithmetic on top of primitives (ML-KEM-768, ML-DSA-65, ECDSA-P256) that are
already proven correct. Given the number of chunks a transaction actually
produced, the number of signatures each strategy issues and the number of
bytes each signature costs follow by construction, not by measurement —
`per_chunk` signs once per chunk, `hash_chain` signs once per checkpoint (or
once total), `buffer_and_sign` signs once, full stop. If predictions
computed purely from that arithmetic and the independently-measured
primitive costs (`results/validation/primitive_bench.json`) match what the
live benchmark harness (`bench/streaming_runner.py`) actually recorded, that
proves the harness introduces no unaccounted overhead, no double-counting,
and no silent divergence between what the strategy is supposed to do and
what it measurably does.

This is the correct and defensible substitute for an external dataset — not
"we couldn't find ground truth so we made do," but "the ground truth for a
measurement-instrument validation is the arithmetic the instrument is
supposed to implement." State it this way in the paper's methodology
section, not as an apology.

`analysis/streaming_model_validation.py` implements this check:

```bash
python -m analysis.streaming_model_validation
python -m analysis.streaming_model_validation --json --output results/streaming_model_validation.json
```

For each row of `results/streaming/*.csv`, it predicts the number of
signatures the recorded strategy must have issued (from that row's own
measured `n_chunks` — not from `ceil(max_tokens / chunk_size_tokens)`, since
a real generation backend's text pieces don't map 1:1 to a token count the
way the synthetic backend's do), then predicts the byte and timing
consequences of that count:

- **Signature bytes are checked as exactly as each scheme's own encoding
  allows.** ML-DSA-65 has a FIPS-204-fixed 3,309-byte signature (confirmed
  byte-exact by `validation/nist_kat.py`), so `full_pqc` predictions are
  checked for **exact** equality — any deviation is a real bug. ECDSA-P256's
  DER encoding is genuinely variable-length (70–72 bytes, a property of the
  SEC1/RFC 3279 ASN.1 encoding, not implementation noise), so `classical`
  and `hybrid` predictions are checked against an **exact integer range**
  (`n_signatures × 70` to `n_signatures × 72`) instead of a single scalar —
  still zero-tolerance arithmetic, just bounded rather than pinned.
- **Signing time is never checked for exact equality.** ML-DSA-65's
  Fiat-Shamir-with-Aborts rejection sampling gives it a genuinely
  right-skewed distribution; the acceptance window used is each scheme's own
  measured p99/median ratio from `primitive_bench.json`, so the tolerance is
  itself derived from measured data rather than picked by hand.

On this project's own data (see the run log in `docs/STREAMING_INTEGRATION.md`
for provenance), **signature-byte predictions matched exactly or fell within
the exact ECDSA range on 100% of validated rows**, across both the committed
real-Llama-3.2-3B sweep and an independent synthetic-backend sweep run at a
different chunk count and repetition depth — the byte arithmetic holds
regardless of what produced the underlying text.

Signing-*time* agreement was initially markedly worse (1/9 rows within
tolerance) and was diagnosed rather than smoothed over. Two hypotheses were
tested directly and ruled out by measurement, not argument, before the real
cause was found:

- **"First use of a freshly generated key is slower"** — refuted.
  Isolated fresh-key-vs.-warm-key timing showed at most a ~1.4× effect for
  ECDSA and ~1.0× for ML-DSA-65, nowhere near the observed multi-hundred-x
  gaps.
- **"Signing cost scales with message size in a way the warm-loop benchmark
  doesn't capture"** — refuted. Signing messages from 32 B to 8 KB in the
  same warm loop `validation/primitive_bench.py` uses moved ECDSA's mean by
  only ~12% (37.75 µs → 42.26 µs) and showed no size trend for ML-DSA-65 at
  all. This could not explain a 30×+ *within-single-call* gap between two
  same-call-count rows (`buffer_and_sign` vs. `hash_chain`, both exactly one
  signature) that differ mainly in message size.

**Confirmed cause: a one-time, per-process ECDSA backend-initialization
cost the warm-loop benchmark cannot see by construction.** Python's
`cryptography` library lazily initializes its OpenSSL-backed EC-signing
support on the *first* ECDSA operation of a process. Measured directly
across 8 independent fresh Python processes, each performing exactly one
ECDSA-P256 sign: **7.7–9.3 ms, consistently**, regardless of message size
(confirmed separately at both 32 B and 2,500 B). The same test against
ML-DSA-65 (this project's from-scratch liboqs ctypes binding, no external
backend to lazily load) showed **0.13–0.33 ms — no cold-start penalty at
all**, actually at or below its own warm-loop mean. `validation/primitive_bench.py`'s
warm loop pays this cost once, on iteration 1 of 200+, invisibly averaged
into a mean that is overwhelmingly the *warm* number; a live server's
`buffer_and_sign` request — the first strategy in `bench/streaming_runner.py`'s
default order, and so typically the very first ECDSA sign call a freshly
started server process ever performs — pays the *full* cold cost, every
time.

This is now implemented as a second, explicit baseline
(`validation.primitive_bench.bench_cold_start_signing()`, `analysis.streaming_model_validation.cold_start_ms_and_tolerance()`),
applied specifically to `buffer_and_sign` rows (not `per_chunk`/`hash_chain`,
which normally run after `buffer_and_sign` against an already-warmed
process in the same sweep — applying the correction there would overclaim
a mechanism not confirmed for those cases). Re-validated against the same
9-row dataset:

| Row | Warm-loop ratio | Cold-start ratio |
|---|---|---|
| classical/buffer_and_sign | 281.24× (tol 1.03×, **FAIL**) | 1.33× (tol 1.50×, **OK**) |
| hybrid/buffer_and_sign | 297.11× (tol 1.03×, **FAIL**) | 1.41× (tol 1.50×, **OK**) |
| full_pqc/buffer_and_sign | 6.00× (tol 3.17×, **FAIL**) | 4.70× (tol 1.78×, **FAIL**) |

The two ECDSA rows — the two largest discrepancies in the entire original
table (281×, 297×) — are fully resolved by the correct baseline.
`full_pqc/buffer_and_sign` stays outside tolerance under *either* baseline,
consistent with the direct measurement showing ML-DSA-65 has no cold-start
effect to correct for.

### Is the remaining 6-row gap noise, or a second systematic effect?

The six remaining out-of-tolerance rows (`classical`/`hybrid` ×
`hash_chain`/`per_chunk`, plus `full_pqc/buffer_and_sign`) were initially
attributed, without a direct test, to "ordinary live-server-vs.-tight-loop
scheduling noise." That label was checked the same way the two earlier
hypotheses were: by measurement. A 5-repetition sweep (synthetic backend,
same reasoning as the cold-start isolation test — this is a
measurement-stability question, not one that needs real generation
content) gives per-repetition ratios, not just a mean:

| Row | Tolerance | Ratios across 5 reps | Pass/5 | Spread (max/min) |
|---|---|---|---|---|
| `full_pqc/per_chunk` | 3.17× | 2.26, 1.67, 2.64, 2.56, 2.80 | **5/5** | 1.68× |
| `full_pqc/buffer_and_sign` | 3.17× | 5.26, 4.28, **3.07**, 5.73, 3.65 | 1/5 | 1.87× |
| `hybrid/per_chunk` | 1.03× | 2.28, 4.15, 3.72, 3.78, 3.57 | 0/5 | 1.82× |
| `classical/per_chunk` | 1.03× | 1.60, 1.57, 1.70, 1.76, 1.58 | 0/5 | **1.12×** |
| `hybrid/hash_chain` | 1.03× | 9.89, 9.46, 8.28, 13.16, **5.24** | 0/5 | 2.51× |
| `classical/hash_chain` | 1.03× | 9.34, 8.95, 12.55, **4.07**, 8.53 | 0/5 | 3.09× |

This does not land as one verdict for all six rows — reported per-row,
honestly, rather than forced into a single label:

- **`full_pqc/per_chunk`: noise, confirmed and resolved.** Every one of
  the 5 repetitions falls *within* tolerance on its own; the original
  single-repetition failure was an unlucky draw, not a real effect. Fixed
  simply by running ≥3 repetitions and validating against the mean —
  matching this project's own convention elsewhere (the main concurrency
  benchmark already uses 5 repetitions for exactly this reason).
- **`full_pqc/buffer_and_sign`: noise-dominated, not yet fully resolved.**
  One of 5 repetitions (3.07×) lands inside tolerance (3.17×), and the
  spread (1.87×) is real — consistent with genuine sampling variance, not
  a fixed multiplier. The mean is still outside tolerance at n=5; more
  repetitions would plausibly close it the way they did for `per_chunk`,
  but this has not yet been confirmed at higher n.
- **`classical/per_chunk`: looks systematic, not noise.** The tightest
  spread of the six (1.12×, ratios clustered at 1.57×–1.76× across all 5
  reps) is the opposite of what sampling noise should look like — a
  genuinely noisy quantity would not reproduce this consistently. This
  reads as a small (~1.6×), real, repeatable effect distinct from both the
  cold-start finding (message-size- and backend-independent, unlike this)
  and from noise.
- **`hybrid/per_chunk`: mixed, leans toward a smaller version of the same
  effect as classical/per_chunk.** More spread (1.82×) than `classical/per_chunk`
  but the same order of magnitude and direction.
- **`classical/hash_chain` and `hybrid/hash_chain`: genuinely noisy, but
  with a floor noise alone doesn't explain.** These show the largest
  rep-to-rep spread of the six (2.5×–3.1×, close to the magnitude that
  would usually indicate real sampling variance) — but even their
  *lowest* observed repetition (4.07×, 5.24×) remains several-fold above
  tolerance. Noise is clearly present here, but it cannot be the *whole*
  story: a purely-noisy quantity centered near the tolerance boundary
  would occasionally dip near or under it at n=5, and neither row does.

**Conclusion: not purely single-repetition noise, and not purely a second
systematic effect either — a genuine mix, confirmed by measurement rather
than assumed.** One row is fully resolved by repetition count alone, one
more is likely to be with further repetitions, and the remaining four show
either a small but clearly reproducible systematic residual
(`classical/per_chunk`, and to a lesser extent `hybrid/per_chunk`) or a
noisy-but-persistently-elevated pattern that repetition count alone will
not fully resolve (`classical/hash_chain`, `hybrid/hash_chain`).

This residual is recorded here, not chased further right now. One
candidate hypothesis for future work, deliberately not tested in this
pass: `per_chunk` and (to a lesser extent) `hash_chain` make many
individual ctypes calls with fresh buffer allocations
(`.from_buffer_copy()`) per call — `validation/primitive_bench.py`'s
isolated loop already pays this same ctypes-marshalling cost on every
iteration, so the open question is not whether ctypes overhead exists (it
does, in both measurements), but whether a *live async server's* memory/GC
pressure (many concurrent live objects from ordinary request handling)
makes each marshal/allocate step measurably slower than the same call
running in an otherwise-idle benchmark process.

**Bottom line for the paper**: signature-*byte* overhead is fully
validated (9/9 exact-or-in-range, unaffected by any of this). Per-signature
*timing* overhead is validated for `buffer_and_sign` on ECDSA configs
(`classical`, `hybrid` — the cold-start-corrected baseline) and for
`full_pqc/per_chunk` (resolved by repetition count). `hash_chain` timing
validation, `classical`/`hybrid` `per_chunk` timing validation, and
`full_pqc/buffer_and_sign` timing validation remain open — cite them as
"validation ongoing," not as confirmed, until a higher-repetition sweep or
further isolation closes the remaining gaps identified above.

## 10. Streaming makes the existing HNDL exposure worse, in proportion to session length

`threats/hndl_capture.py` already establishes PQ-Shield's core
harvest-now-decrypt-later (HNDL) finding — see `docs/DESIGN.md` H3 — for
one small, fixed-size classifier response: a passive adversary who records
the key-establishment blob and the response ciphertext gets nothing usable
under Configuration B/C (ML-KEM-768 is not broken by Shor's algorithm) and
everything usable under Configuration A (RSA-2048 is). That result is
bounded and fixed-size by construction.

`threats/streaming_hndl_experiment.py` extends it to what actually changes
for a streaming AI API: **a single handshake's session key is established
once and reused for every chunk of a potentially long-running stream** (a
multi-turn chat session, an agent's full reasoning trace, a long
completion). This is **not a new vulnerability class** — it is the same
Shor's-algorithm-breaks-RSA/ECDH threat, made worse in direct proportion to
how long the stream runs, because streaming's whole design point (one
handshake, many chunks) is exactly what maximizes the payoff of harvesting
a single broken handshake.

**Measured result** (live capture against all three configs, synthetic
generation backend for fast/deterministic verification — the finding
depends only on ciphertext byte counts, not on what produced the
plaintext, exactly as the byte-level streaming-signature findings above
do not depend on backend either):

| max_tokens | classical: bytes decryptable under future CRQC | hybrid / full_pqc: bytes decryptable under future CRQC |
|---|---|---|
| 50 | 729 | 0 |
| 200 | 2,953 | 0 |
| 500 | 7,400 | 0 |
| 2,000 | 29,674 | 0 |

Classical's exposure is **100% of harvested response content, at every
length, growing linearly with response length** — once RSA-2048 key
transport is broken, the one session key it protected decrypts everything
that session ever streamed. Hybrid and full_pqc's exposure is **0%,
regardless of length** — both use ML-KEM-768 for key establishment, which
is what confidentiality depends on here, so both are **equally and
completely effective** against this threat; classical is **completely
ineffective**, and the cost of that ineffectiveness compounds with every
additional token streamed, unlike the bounded exposure the single-shot
experiment measures.

**What an HNDL adversary's stored-bytes figure does and does not include**:
`kex_blob` (once per session) and every chunk's `(nonce, ciphertext)` pair
— never signatures or chain hashes, which protect authenticity, not
confidentiality, and buy an eavesdropper nothing towards decrypting content
later. (`threats/hndl_capture.py`'s own `total_bytes_stored` figure, by
contrast, does include signature bytes — a reasonable choice for "total
artifact volume an adversary would archive," but a different question from
"bytes that become decryptable." The streaming experiment reports the two
separately and does not follow that convention where they'd diverge.)

**Strategy-independence check, run empirically rather than assumed**: at
one fixed response length, `per_chunk` and `hash_chain` produced
byte-identical confidentiality exposure (both chunk the same generated
content into the same number of independent AEAD envelopes). `buffer_and_sign`
did **not** match exactly — it was smaller by precisely
`(n_chunks - 1) x 28 bytes` (a 12-byte GCM nonce + 16-byte authentication
tag per additional AEAD envelope; `buffer_and_sign` pays this once, for the
whole response, while `per_chunk`/`hash_chain` pay it once per chunk). This
is real, fully explained by AES-GCM's per-envelope overhead, and confirmed
against the live measurement (10 chunks, predicted delta 252 B, measured
delta 252 B) — not a bug, and not a confidentiality difference between
strategies in the sense that matters here: which bytes are recoverable
under a future CRQC is unaffected (kex-decryptability alone drives the
0%-vs-100% finding above), only the small fixed per-envelope overhead
differs.

### A separate, unrelated finding surfaced by the same capture: traffic-shape metadata exposure

This is **not an HNDL/confidentiality finding** — do not read it as one, and
do not sum its byte counts into the table above. `per_chunk` and
`hash_chain` both put one wire-visible SSE event on *every* chunk (a
signature, or a chain hash, riding alongside that chunk's ciphertext),
which reveals the exact chunk count and inter-chunk arrival timing to a
passive network observer with **zero cryptanalysis** — timing that
plausibly correlates with generation rate/content. `buffer_and_sign`
reveals only one final event, with no intermediate wire structure exposed
during generation.

This is a caveat on `hash_chain`'s otherwise-strong recommendation from
section 2 above, not a reversal of it: `hash_chain` still wins decisively
on signature-byte cost and still fully protects confidentiality (see
above); it simply also happens to reveal stream cadence to a passive
observer, exactly as much as `per_chunk` does and strictly more than
`buffer_and_sign` does. If a deployment's threat model cares about hiding
*that a stream is happening at a given cadence* (not just its content),
that is a reason to prefer `buffer_and_sign` specifically, independent of
its worse time-to-first-token and independent of the HNDL finding above.

## 11. Known limitations / honest gaps

- **Not yet wired into the Streamlit dashboard.** The `webapp/` pages don't
  have a streaming view yet. The CLI/Python path above is fully functional;
  a `pages/5_Streaming_Demo.py` page showing chunks arriving live (similar
  to the existing Live Demo page's tamper toggle) would be a natural
  follow-up, reusing `api/secure_streaming_client.py` directly.
- **The streaming endpoint is not load-tested under concurrency** (see §8) —
  don't cite streaming numbers as representative of concurrent-load
  behavior; that's what the main `bench/orchestrator.py` sweep is for.
- **Real-backend timing has not been collected in this repository yet** —
  every number in §2 above comes from the synthetic backend. Once you run a
  real backend on your own hardware, replace those numbers with real ones
  before citing them, and keep the `real_inference` disclosure alongside
  whichever you report.
- **liboqs/ML-DSA signing cost is per-call, not amortized across a batch** —
  `per_chunk`'s cost could in principle be reduced by batch-signing multiple
  chunks at once if your threat model tolerates a small latency buffer per
  batch; that variant is not implemented here and would be a reasonable
  fourth strategy to add if reviewers ask for it.
