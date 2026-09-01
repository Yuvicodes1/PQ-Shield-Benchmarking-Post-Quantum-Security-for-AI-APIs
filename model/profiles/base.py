"""Shared interface for every AI payload profile.

A payload profile is a stand-in for one shape of real AI inference API
traffic -- it produces a request body and computes a response body of a
specific realistic size, so the crypto layer can be measured against
something other than a single fixed workload. See docs/DESIGN.md
"Payload profiles" for the full rationale and the honesty disclosure on
which profiles use real model compute versus a synthetic, size-matched
generator.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class PayloadProfile(ABC):
    name: str
    description: str

    # True: a genuine trained/fixed-weight model actually runs on the
    # request. False: a deterministic, size-matched synthetic generator
    # stands in for a model that would be impractical to run in this
    # project's benchmark loop (see embedding.py / llm_completion.py).
    # This flag is surfaced in every figure/table that reports on a
    # profile, so a reader is never left assuming real inference occurred
    # where it did not.
    real_inference: bool

    @abstractmethod
    def sample_request(self) -> dict:
        """Returns a JSON-serializable request body for this profile."""
        raise NotImplementedError

    @abstractmethod
    def predict(self, request_body: dict) -> dict:
        """Returns a JSON-serializable response body. MUST include a
        '_inference_ms' key recording server-side compute time; callers
        pop this key before the response is serialized onto the wire."""
        raise NotImplementedError
