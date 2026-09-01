"""Payload profile: llm_completion.

Chat/completion endpoint. NOT a real language model -- generates a
target-length block of deterministic pseudo-text seeded from the prompt's
hash. Represents the traffic shape of an OpenAI-style chat completion
API -- exactly the case named in this project's own motivating example
("hosted on OpenAI, AWS SageMaker, or custom FastAPI/Flask servers"):
small prompt request, large generated-text response.

Honesty disclosure (see docs/DESIGN.md "Payload profiles"): `real_inference
= False`. This profile's `_inference_ms` measures hashing + PRNG-driven
text assembly cost only, not real LLM inference (which would require an
actual language model and is computationally impractical to run for every
request in this benchmark loop). It exists purely to give the
payload-shape sensitivity study the "small in, large out" extreme most
associated with modern conversational AI APIs.
"""

from __future__ import annotations

import hashlib
import time

import numpy as np

from .base import PayloadProfile

_SAMPLE_PROMPTS = (
    "Summarize the key risks of migrating a production API to post-quantum cryptography, "
    "focusing on latency-sensitive workloads.",
    "Explain the difference between a hybrid and a fully post-quantum key exchange scheme "
    "in the context of TLS 1.3.",
    "Write a short incident report describing a suspected harvest-now-decrypt-later data "
    "exfiltration attempt against a healthcare API.",
)

_WORD_BANK = (
    "quantum lattice cryptography inference latency payload signature ciphertext handshake "
    "concurrency endpoint model classifier response request overhead encryption "
    "authentication verification adversary threat harvest decrypt resilient scalable "
    "throughput benchmark empirical framework architecture migration deployment"
).split()

DEFAULT_TARGET_CHARS = 4000  # ~4KB generated completion, tunable via max_tokens in the request


class LLMCompletionProfile(PayloadProfile):
    name = "llm_completion"
    description = (
        "Chat/completion endpoint (synthetic, deterministic text generator -- not a real LLM) -- "
        "small request (prompt), large response (generated text, ~4KB default). Represents an "
        "OpenAI-style chat completion API."
    )
    real_inference = False

    def __init__(self) -> None:
        self._rng = np.random.default_rng(7)

    def sample_request(self) -> dict:
        prompt = _SAMPLE_PROMPTS[int(self._rng.integers(0, len(_SAMPLE_PROMPTS)))]
        return {"prompt": prompt, "max_tokens": DEFAULT_TARGET_CHARS // 5}

    def predict(self, request_body: dict) -> dict:
        t0 = time.perf_counter()
        prompt = request_body.get("prompt", "")
        target_chars = int(request_body.get("max_tokens", DEFAULT_TARGET_CHARS // 5)) * 5

        digest = hashlib.sha256(prompt.encode()).digest()
        seed = int.from_bytes(digest[:8], "big") % (2**32)
        rng = np.random.default_rng(seed)

        words = []
        length = 0
        while length < target_chars:
            w = _WORD_BANK[int(rng.integers(0, len(_WORD_BANK)))]
            words.append(w)
            length += len(w) + 1
        text = " ".join(words)
        text = text[0].upper() + text[1:] + "."

        inference_ms = (time.perf_counter() - t0) * 1000
        return {
            "completion": text,
            "tokens_generated": len(words),
            "_inference_ms": inference_ms,
        }
