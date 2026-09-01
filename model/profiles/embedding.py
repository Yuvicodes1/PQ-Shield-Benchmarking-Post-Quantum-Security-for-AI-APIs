"""Payload profile: embedding.

Text-embedding endpoint. NOT a real transformer -- generates a
deterministic pseudo-embedding vector by seeding a PRNG from a SHA-256
hash of the input text. Represents a semantic-search / RAG embedding
endpoint's traffic shape: small-to-medium text request, large dense-vector
response (768-d, matching common embedding-model output sizes).

Honesty disclosure (see docs/DESIGN.md "Payload profiles"): `real_inference
= False`. This profile's `_inference_ms` measures hashing + PRNG +
serialization cost only, not real embedding-model compute, which would be
computationally impractical to run for every request in this project's
benchmark loop. It exists purely to give the payload-shape sensitivity
study a request/response size point in the "small in, large out" region
that tabular_small and image_cnn do not cover.
"""

from __future__ import annotations

import hashlib
import time

import numpy as np

from .base import PayloadProfile

EMBEDDING_DIM = 768  # matches common embedding-model output sizes (e.g. BERT-base)

_SAMPLE_TEXTS = (
    "Patient presents with elevated troponin levels and intermittent chest pain over the past "
    "48 hours, with a family history of coronary artery disease and controlled hypertension on "
    "lisinopril.",
    "Quarterly revenue grew 12 percent year over year, driven primarily by expansion in the "
    "enterprise segment, while gross margin compressed slightly due to increased cloud "
    "infrastructure spend.",
    "The transaction was flagged for review due to an unusual velocity of transfers across "
    "newly created accounts within a fifteen minute window, originating from a previously "
    "dormant IP range.",
)


class EmbeddingProfile(PayloadProfile):
    name = "embedding"
    description = (
        "Text-embedding endpoint (synthetic, deterministic -- not a real transformer) -- "
        "small-medium request (text), large response (768-d float vector). Represents a "
        "semantic-search/RAG embedding endpoint."
    )
    real_inference = False

    def __init__(self) -> None:
        self._rng = np.random.default_rng(42)

    def sample_request(self) -> dict:
        text = _SAMPLE_TEXTS[int(self._rng.integers(0, len(_SAMPLE_TEXTS)))]
        return {"text": text}

    def predict(self, request_body: dict) -> dict:
        t0 = time.perf_counter()
        text = request_body.get("text", "")
        digest = hashlib.sha256(text.encode()).digest()
        seed = int.from_bytes(digest[:8], "big") % (2**32)
        rng = np.random.default_rng(seed)
        vec = rng.normal(0, 1, size=EMBEDDING_DIM)
        vec = vec / np.linalg.norm(vec)
        inference_ms = (time.perf_counter() - t0) * 1000
        return {
            "embedding": [round(float(v), 6) for v in vec],
            "dim": EMBEDDING_DIM,
            "_inference_ms": inference_ms,
        }
