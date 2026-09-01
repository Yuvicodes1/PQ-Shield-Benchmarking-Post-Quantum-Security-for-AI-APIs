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

## 9. Known limitations / honest gaps

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
