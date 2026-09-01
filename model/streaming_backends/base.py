"""Shared interface for streaming text-generation backends.

A backend produces the token/text stream a streaming payload profile sends
over the wire. It has nothing to do with cryptography -- crypto/streaming.py
handles signing, this handles generation. Three implementations:

  synthetic_backend.py     No dependencies, deterministic, simulated timing.
                            Works everywhere, including this project's own
                            CI/sandbox. Use for developing and testing the
                            streaming protocol itself.
  llama_cpp_backend.py     Real backend, requires llama-cpp-python + a local
                            GGUF model file. Genuine inference, genuine timing.
  transformers_backend.py  Real backend, requires transformers + torch + a
                            local or hub model. Genuine inference, genuine timing.

Selection is via model/streaming_backends/registry.py, driven by the
PQ_SHIELD_STREAMING_BACKEND environment variable. See docs/STREAMING.md for
setup instructions for the two real backends.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator


class StreamingBackend(ABC):
    name: str
    real_inference: bool  # False only for synthetic_backend

    @abstractmethod
    def stream(self, prompt: str, max_tokens: int) -> Iterator[str]:
        """Yields successive text pieces as they are generated. Granularity
        (single token vs. a few characters) is backend-defined; callers
        should not assume one piece == one token."""
        raise NotImplementedError
