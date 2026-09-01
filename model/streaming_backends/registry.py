"""Selects and caches the active streaming backend, driven by the
PQ_SHIELD_STREAMING_BACKEND environment variable (default: synthetic).

Caching is a singleton, not per-call: constructing LlamaCppStreamingBackend
or TransformersStreamingBackend loads a model into memory, which must happen
once per server process, not once per request.
"""

from __future__ import annotations

import os

from .base import StreamingBackend

BACKEND_NAMES = ["synthetic", "llama_cpp", "transformers"]

_instance: StreamingBackend | None = None


def get_backend(name: str | None = None) -> StreamingBackend:
    global _instance
    if _instance is not None:
        return _instance

    name = name or os.environ.get("PQ_SHIELD_STREAMING_BACKEND", "synthetic")

    if name == "synthetic":
        from .synthetic_backend import SyntheticStreamingBackend
        _instance = SyntheticStreamingBackend()
    elif name == "llama_cpp":
        from .llama_cpp_backend import LlamaCppStreamingBackend
        _instance = LlamaCppStreamingBackend()
    elif name == "transformers":
        from .transformers_backend import TransformersStreamingBackend
        _instance = TransformersStreamingBackend()
    else:
        raise ValueError(f"Unknown PQ_SHIELD_STREAMING_BACKEND={name!r}. Valid: {BACKEND_NAMES}")

    return _instance


def reset_backend_cache() -> None:
    """Testing/dashboard hook: forces the next get_backend() call to
    reconstruct the backend (e.g. after changing the env var mid-process)."""
    global _instance
    _instance = None
