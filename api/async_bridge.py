"""Bridges a blocking synchronous generator into an async iterator without
blocking the event loop.

Why this exists: model/streaming_backends/*.stream() is a plain synchronous
generator (llama-cpp-python and transformers' TextIteratorStreamer are both
naturally synchronous APIs; the synthetic backend uses time.sleep()). The
FastAPI SSE endpoint in api/secure_app.py is an async generator. Calling a
blocking `for token in backend.stream(...):` directly inside an `async def`
would block the entire event loop for the duration of each blocking call --
fine for a single request in isolation, but it would stall every other
concurrent request this server process is handling, which defeats the
purpose of using an async framework at all.

This runs each `next()` call in the default thread pool executor, so the
event loop stays free to service other requests while a chunk is being
generated.

Known limitation (stated once, not re-derived per file): the streaming
endpoint is designed for measuring per-transaction signing overhead at low
to moderate concurrency, not for the high-concurrency load sweeps
bench/orchestrator.py performs on the non-streaming endpoints. Running many
concurrent streaming transactions against a real model backend is bounded
by the model's own throughput (one GPU/CPU doing generation for everyone),
which is a property of the backend, not of this bridge.
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator, Iterator, TypeVar

T = TypeVar("T")
_SENTINEL = object()


async def aiter_sync_generator(gen: Iterator[T]) -> AsyncIterator[T]:
    loop = asyncio.get_event_loop()
    it = iter(gen)
    while True:
        item = await loop.run_in_executor(None, next, it, _SENTINEL)
        if item is _SENTINEL:
            return
        yield item
