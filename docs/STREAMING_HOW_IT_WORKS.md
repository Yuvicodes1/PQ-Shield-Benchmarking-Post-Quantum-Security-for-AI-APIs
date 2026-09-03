# How LLM Streaming Works in PQ-Shield

A mechanism-level walkthrough of the token-streaming feature: what happens,
in what order, from the moment a client asks for a streamed completion to
the moment it has a verified, reconstructed response. This is the "how does
it actually work" companion to the other two streaming docs:

- [`docs/STREAMING.md`](STREAMING.md) — *why it exists*, the three signing
  strategies' cost trade-offs with measured numbers, and how to run/configure
  it (env vars, CLI sweeps, real-model setup).
- [`docs/STREAMING_INTEGRATION.md`](STREAMING_INTEGRATION.md) — a dated log
  of *what was built*, in what order, what broke, and how each piece was
  verified during development.

Read this one if you want to understand the machinery itself: which module
does what, what crosses the wire, and why each design choice is shaped the
way it is.

---

## 1. The problem, in one sentence

Every other endpoint in this project signs one complete response in one
call — impossible for a token-by-token LLM stream, because you cannot sign
bytes you have not generated yet. The whole feature is the answer to "so
what do you sign, and when?"

## 2. The moving parts

Five layers, each a separate module, each replaceable independently:

```
prompt                                                    verified text
  │                                                              ▲
  ▼                                                              │
┌─────────────┐   ┌──────────┐   ┌───────────┐   ┌─────┐   ┌──────────┐
│  generation  │→→│ chunking │→→│  signing   │→→│ SSE │→→│ client   │
│  backend     │   │ (server) │   │  strategy  │   │wire │   │verifier  │
└─────────────┘   └──────────┘   └───────────┘   └─────┘   └──────────┘
model/streaming_   api/secure_    crypto/           text/     crypto/streaming.py
backends/          app.py         streaming.py      event-    (verify_*) +
                   event_          (server side)     stream    api/secure_
                   generator()                                 streaming_client.py
```

Everything is orchestrated by one FastAPI route,
[`POST /secure/predict/stream`](../api/secure_app.py) in `api/secure_app.py`,
and consumed by [`api/secure_streaming_client.py`](../api/secure_streaming_client.py)
(CLI/benchmark path) or [`webapp/demo_transaction.py`](../webapp/demo_transaction.py)'s
`run_streaming_transaction_live()` (dashboard path — same logic, yields
per-chunk UI events instead of one final dict).

## 3. Step by step

### 3.1 Handshake (unchanged from non-streaming)

The client does the same `GET /secure/handshake` → key-establishment →
session-key dance as the ordinary `/secure/predict` endpoint (see
`crypto/base.py`, `ServerCryptoConfig` / `ClientCryptoConfig`). Streaming
adds nothing new here — one handshake, one session key, reused for every
chunk of the response that follows.

### 3.2 The request

The client AEAD-encrypts a small JSON body under the session key, same
envelope shape (`nonce`, `ciphertext`) as every other request in this
project — the only difference is what's *inside* the plaintext:

```json
{"prompt": "...", "strategy": "hash_chain", "chunk_size_tokens": 5, "max_tokens": 200}
```

No new request schema was needed (`api/schemas.py`'s `SecurePredictRequest`
is reused as-is) — streaming-specific parameters just ride inside the
already-encrypted plaintext body.

### 3.3 Server: decrypt, then pick a backend and a strategy

`secure_predict_stream()` in `api/secure_app.py` decrypts the request,
reads `strategy`/`chunk_size_tokens`/`max_tokens`/`checkpoint_interval` out
of the plaintext, then constructs:

- a **signing strategy** instance via `crypto.streaming.get_server_strategy()`
  — one of `BufferAndSignStrategy`, `PerChunkStrategy`, `HashChainStrategy`
  (§4 below), scoped to this one transaction (holds the session key, the
  handshake id, and any strategy-specific running state like the hash
  chain's running digest).
- the **generation backend**, via `model.streaming_backends.registry.get_backend()`
  — a process-wide singleton (§5 below), *not* constructed per-request,
  because the two real backends load a model into memory.

### 3.4 Generation → chunking

The backend's `stream(prompt, max_tokens)` yields small text pieces one at
a time (granularity is backend-defined — "a token" for the real backends,
"a word" for the synthetic one; callers never assume a fixed size). The
server buffers pieces in `token_buffer` and flushes into a chunk once
`chunk_size_tokens` pieces have accumulated:

```python
async for token in aiter_sync_generator(backend.stream(prompt, max_tokens)):
    token_buffer.append(token)
    if len(token_buffer) >= chunk_size_tokens:
        yield flush_buffer()   # -> strategy.add_chunk(text.encode(), index)
```

`chunk_size_tokens` is the knob that trades time-to-first-chunk against
per-chunk overhead — 1 = every generated piece is its own chunk (maximum
overhead, minimum latency to see *something*); larger values batch more
text per signed/chained unit.

**Why `aiter_sync_generator`:** `llama-cpp-python` and `transformers`'
`TextIteratorStreamer` are both plain blocking Python generators — a raw
`for token in backend.stream(...)` inside an `async def` route would freeze
FastAPI's entire event loop for the duration of each blocking call, stalling
every other concurrent request on the same server process.
[`api/async_bridge.py`](../api/async_bridge.py)'s `aiter_sync_generator()`
runs each `next()` call in the default thread-pool executor instead, so the
event loop stays free while a chunk is being generated. This is a plumbing
concern, not a crypto one — it exists purely because generation is
inherently synchronous and FastAPI's SSE response is inherently async.

### 3.5 Signing (per chunk, strategy-dependent)

Each flushed chunk's plaintext bytes go through `strategy.add_chunk(plaintext,
index)`, which does the AEAD encryption (always) and, depending on the
strategy, some or none of the signing (§4). This returns a wire-ready dict
or `None` (strategies that withhold everything until the end).

### 3.6 The wire format (SSE)

The response is `text/event-stream` with `Cache-Control: no-cache` and
`X-Accel-Buffering: no` (defeats any intermediary buffering proxy, since
buffering would defeat the whole point of streaming). Every chunk dict is
JSON-encoded onto one `data:` line, with byte fields
(`nonce`/`ciphertext`/`signature`/`chain_hash`) base64-encoded for text
transport:

```
data: {"kind":"chunk","index":0,"nonce":"...","ciphertext":"...","signature":"...","sign_ms":0.31,"signature_bytes":3309}

data: {"kind":"chunk","index":1,"nonce":"...","ciphertext":"...","signature":"...","sign_ms":0.29,"signature_bytes":3309}

data: {"kind":"final_chain","final_chain_hash":"...","n_chunks":40,"signature":"...","sign_ms":0.30,"signature_bytes":3309}

event: done
data: {"n_chunks":40,"total_ms":1284.2}
```

`kind` disambiguates the four possible line shapes a client will ever see:
`"chunk"` (one per flushed chunk — always present for `per_chunk` and
`hash_chain`, never for `buffer_and_sign`), `"final_buffered"` (the single
line `buffer_and_sign` ever sends), `"final_chain"` (`hash_chain`'s
terminating signed hash), and the trailing `event: done` line (no `"kind"`
field — carries only `n_chunks`/`total_ms` bookkeeping, not verification
data). Client code must key off `kind` rather than line order or an
`else` catch-all — an early version of the sequence-attack experiment
(`docs/STREAMING_INTEGRATION.md` §8) mistook the `done` trailer for the
real final signed event because of exactly that mistake.

The server calls `server_crypto.forget(handshake_id)` once the stream ends,
same handshake-cleanup discipline as the non-streaming route.

### 3.7 Client: consuming and verifying live

`api/secure_streaming_client.py`'s `run_streaming_transaction()` (and the
dashboard's `run_streaming_transaction_live()` variant) reads
`resp.aiter_lines()`, and for every `data:` line:

1. Records **time-to-first-token** the instant the *first* `data:` line of
   any kind arrives.
2. Base64-decodes the byte fields.
3. Dispatches on `kind` to the matching verifier in `crypto/streaming.py`
   (`verify_per_chunk`, `verify_hash_chain_chunk`, `verify_buffer_and_sign_final`,
   `verify_hash_chain_final`) — each returns whether the AEAD decryption
   succeeded, whether a signature (if present) verified, and for
   `per_chunk`, whether the chunk arrived at its expected sequence index.
4. Accumulates decrypted plaintext into the reconstructed response and
   folds per-chunk metrics (signing ms, verify ms, signature bytes) into a
   running total.
5. On the terminating event, finalizes `stream_fully_verified` — either
   from `hash_chain`'s explicit chain-matches-and-signature-valid check, or
   (for the other two strategies, which have no separate terminating
   check) from the AND of every per-chunk/per-final check seen so far.

The dashboard's live variant differs only in *shape*: instead of returning
one flat dict after the whole stream is consumed, it's an async generator
yielding one UI event per chunk (`{"type": "chunk", "text": ..., "signature_valid":
..., ...}`) so the Streamlit page can render tokens and verification badges
as they arrive, plus a final `{"type": "summary", "metrics": ...}` event at
the end. It also supports live tamper-injection (corrupting one chosen
chunk's ciphertext or signature bytes before verification) for the demo's
"show it catching an attack" UI.

## 4. The three signing strategies, mechanically

All three live in [`crypto/streaming.py`](../crypto/streaming.py) and share
one interface (`add_chunk(plaintext, index) -> dict | None`,
`finalize(n_chunks) -> dict | None`). AES-256-GCM encrypts every chunk's
own bytes immediately in all three — that guarantee never depends on
signing. What differs is **when the asymmetric signature happens** and
**what it covers**.

### `buffer_and_sign`

`add_chunk()` just appends plaintext to an in-memory buffer and returns
`None` — nothing is sent to the client per chunk. `finalize()` encrypts the
*entire* accumulated buffer as one AEAD envelope and signs it once. One
signature total, but the client sees nothing until generation is
completely finished — streaming's latency benefit is fully defeated for
the sake of minimal signature bytes.

### `per_chunk`

`add_chunk()` encrypts and signs on every call:

```python
signed_bytes = index_bytes(index) + nonce + ciphertext
signature, meta = server_crypto.sign(handshake_id, signed_bytes)
```

Signing `index || nonce || ciphertext` — not just `nonce || ciphertext` —
is deliberate: it binds the chunk's *position in the sequence* into what
gets signed. A naive scheme that signs only the envelope would let an
active adversary silently swap or drop independently-valid chunks (each
one's signature still verifies fine on its own — nothing about it says
where it belongs). Binding the index means the client's
`verify_per_chunk()` can independently track an expected running counter
(`expected_index`) and flag any gap or reordering, in addition to the
ordinary signature check. See
`tests/test_streaming_signing.py::test_per_chunk_detects_reordering`.

Cost: N signatures for N chunks — for ML-DSA-65 (3,309 bytes/signature) at
one-chunk-per-token over a long response, that adds up to hundreds of KB of
signature overhead alone (§2 of `docs/STREAMING.md` has the measured
numbers).

### `hash_chain`

`add_chunk()` encrypts every chunk immediately (so per-chunk tamper
detection via AEAD is still instant) but does **not** sign it. Instead it
folds the chunk into a running SHA-256 chain:

```python
running_hash = sha256(running_hash + index_bytes(index) + nonce + ciphertext)
```

starting from a fixed 32-byte genesis value. Only the *final* chain hash
gets signed — once at `finalize()`, and optionally also at intermediate
checkpoints (`checkpoint_interval`) if you want partial verifiability
before the stream ends without paying for a signature on every chunk.

Why this closes the reordering problem *by construction*, not by a
side-channel index check: each link's hash depends on every previous
link's hash. Reordering, dropping, or forging any chunk anywhere in the
sequence changes every hash computed after that point, which the client
is independently recomputing chunk-by-chunk (`HashChainClientState.absorb()`)
and finally compares against the server's signed terminal hash. One
signature total (or one per checkpoint), same low cost as
`buffer_and_sign`, but chunks still arrive as soon as they're generated.

**The trade-off this doesn't remove**: sequence integrity — "every chunk
present, correctly ordered, nothing swapped" — is only *confirmed* once the
terminating signature arrives and matches. Until then, a client has
received and decrypted chunks whose relative position hasn't been
cryptographically confirmed yet — an attacker who reorders/drops
mid-stream is caught, but only once the stream ends, by which point (in a
real chat UI) the corrupted text may already have been shown to the user.
This is exactly what `threats/streaming_mitm_experiment.py` measures (see
`docs/STREAMING_INTEGRATION.md` §8): `per_chunk` catches a reordering
attack at the very next chunk (~50% of the response delivered before
detection, in the recorded runs); `hash_chain` doesn't flag anything until
the final signature — 100% of the (tampered) response delivered first. It
is a documented cost of amortizing the signature, not a bug.

## 5. The three generation backends

[`model/streaming_backends/`](../model/streaming_backends/) implements one
tiny interface (`StreamingBackend.stream(prompt, max_tokens) -> Iterator[str]`)
three times, selected once per server process by
`model.streaming_backends.registry.get_backend()` (driven by the
`PQ_SHIELD_STREAMING_BACKEND` env var, default `synthetic`, cached as a
singleton because the two real backends load a model into memory):

| Backend | `real_inference` | What `stream()` actually does |
|---|---|---|
| `synthetic` | `False` | Seeds a PRNG from `sha256(prompt)`, yields words from a fixed word bank at a simulated per-token delay (`PQ_SHIELD_SYNTHETIC_TOKENS_PER_SEC`, default 30). Zero dependencies, deterministic, works anywhere. |
| `llama_cpp` | `True` | Real decoding via `llama-cpp-python` against a local GGUF file (`PQ_SHIELD_LLAMA_MODEL_PATH`). |
| `transformers` | `True` | Real decoding via Hugging Face `transformers` + `torch`, using `TextIteratorStreamer` under the hood. |

This backend choice is **orthogonal to everything in §4** — the signing
strategies operate on whatever bytes the backend produces, chunked at
whatever `chunk_size_tokens` the request asked for. Swapping backends
changes generation *timing* (useful for a realistic time-to-first-token
number against real decode speed); it does not change which strategy signs
what, or the signature-byte-overhead finding, which depends only on chunk
count and size. See `docs/STREAMING.md` §5 for how to install and point at
a real model.

*Naming note, not to be confused with the above*: `model/profiles/llm_completion.py`
is a different thing — a **non-streaming** payload-shape profile (small
prompt in, one large synthetic text blob out, all at once) used by the
main single-shot benchmark sweep to study payload-size sensitivity. It
shares the "LLM-shaped traffic" motivation but has nothing to do with the
streaming/SSE machinery this document describes.

## 6. Where this surfaces in the dashboard

Four Streamlit pages under `pages/` consume this machinery, all documented
in detail (what was built, how verified) in `docs/STREAMING_INTEGRATION.md`
§4–§6 and §8:

- **Live Demo** (`1_🔴_Live_Demo.py`) — a "🌊 Streaming Response (SSE)" tab:
  pick config/strategy/prompt/chunk size, watch tokens and per-chunk
  verification badges arrive live, with a tamper toggle to watch detection
  happen in real time. Backed by `webapp/demo_transaction.run_streaming_transaction_live()`.
- **Benchmark Runner** (`2_🚀_Benchmark_Runner.py`) — a "🌊 Streaming Sweep"
  tab wrapping `bench.streaming_runner.run_sweep` (configs × strategies ×
  response lengths × chunk sizes), with a synthetic/real-backend selector.
- **Results Dashboard** (`3_📊_Results_Dashboard.py`) — a "🌊 Streaming
  Response Overhead" section: TTFT-by-strategy and signature-bytes-by-strategy
  charts plus a strategy-comparison table, reading `results/streaming/*.csv`
  via `analysis.streaming_analysis`.
- **Threat Scenarios** (`4_🛡️_Threat_Scenarios.py`) — a "🌊 Streaming
  Sequence Attack" tab running `threats.streaming_mitm_experiment`, which
  drops/reorders a chunk mid-stream and measures how much of the response
  each strategy delivers before catching it (§4 above).

## 7. File map

| Concern | File |
|---|---|
| Signing strategies (server + client verifiers) | `crypto/streaming.py` |
| Generation backend interface + implementations | `model/streaming_backends/{base,synthetic_backend,llama_cpp_backend,transformers_backend,registry}.py` |
| Sync-generator → async-SSE bridge | `api/async_bridge.py` |
| The SSE route itself | `api/secure_app.py` → `POST /secure/predict/stream` |
| CLI/benchmark client | `api/secure_streaming_client.py` |
| Live dashboard client | `webapp/demo_transaction.py` → `run_streaming_transaction_live()` |
| Sweep driver | `bench/streaming_runner.py` |
| Result aggregation | `analysis/streaming_analysis.py` |
| Sequence-attack experiment | `threats/streaming_mitm_experiment.py` |
| Correctness tests | `tests/test_streaming_signing.py` |

---

For measured numbers, environment variables, and step-by-step commands to
run any of this yourself, see [`docs/STREAMING.md`](STREAMING.md). For the
history of how it was merged, wired into the dashboard, and debugged, see
[`docs/STREAMING_INTEGRATION.md`](STREAMING_INTEGRATION.md).
