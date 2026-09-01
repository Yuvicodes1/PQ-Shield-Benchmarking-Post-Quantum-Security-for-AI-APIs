"""Synthetic streaming backend.

No dependencies, deterministic, and works in any environment including a
network-restricted sandbox with no GPU -- this is what PQ-Shield's own CI
and the sandboxed development environment run against. It simulates a
plausible per-token generation delay (default 30 tokens/sec, roughly a
small quantized model decoding on CPU) so that time-to-first-token and
total-generation-time measurements are non-degenerate, but the delay is
simulated, not measured from a real model.

`real_inference = False` on this class is the disclosure: any figure or
table built from this backend must say so, exactly as model/profiles/
already discloses synthetic vs. real compute for the payload-shape study.
Use llama_cpp_backend.py or transformers_backend.py for genuine timing.
"""

from __future__ import annotations

import hashlib
import os
import time

import numpy as np

from .base import StreamingBackend

_WORD_BANK = (
    "quantum lattice cryptography inference latency payload signature ciphertext "
    "handshake concurrency endpoint model classifier response request overhead "
    "encryption authentication verification adversary threat harvest decrypt "
    "resilient scalable throughput benchmark empirical framework architecture "
    "migration deployment stream token chunk checkpoint hash chain signed"
).split()


class SyntheticStreamingBackend(StreamingBackend):
    name = "synthetic"
    real_inference = False

    def __init__(self, tokens_per_second: float | None = None):
        self.tokens_per_second = tokens_per_second or float(
            os.environ.get("PQ_SHIELD_SYNTHETIC_TOKENS_PER_SEC", "30")
        )

    def stream(self, prompt: str, max_tokens: int):
        delay_s = (1.0 / self.tokens_per_second) if self.tokens_per_second > 0 else 0.0
        digest = hashlib.sha256(prompt.encode()).digest()
        seed = int.from_bytes(digest[:8], "big") % (2**32)
        rng = np.random.default_rng(seed)

        for _ in range(max_tokens):
            if delay_s:
                time.sleep(delay_s)
            word = _WORD_BANK[int(rng.integers(0, len(_WORD_BANK)))]
            yield word + " "
