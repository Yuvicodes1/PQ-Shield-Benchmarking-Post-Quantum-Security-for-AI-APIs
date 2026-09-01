"""Payload profile: image_cnn.

32x32x3 image classifier -- a small convolutional network (conv -> relu ->
maxpool, twice, then a dense softmax head) implemented directly in NumPy
with a fixed, deterministically-seeded set of weights.

Honesty disclosure (see docs/DESIGN.md "Payload profiles"): this network's
weights are NOT trained on labeled data -- there is no meaningful
classification accuracy to report, and none is claimed. What this profile
measures honestly is (a) a request payload roughly 10x larger than
tabular_small's (a base64-encoded 32x32x3 image, ~4KB) against (b) genuine,
non-trivial floating-point convolution compute on the server, not a
sleep()-simulated delay. That combination is what the payload-shape
sensitivity study needs: a real inference-shaped cost, at a larger,
vision-classifier-realistic payload size, with zero external dataset
download dependency (consistent with this project's zero-download,
fully-reproducible design philosophy -- see the tabular_small profile and
the original choice of sklearn's load_digits() over a downloaded dataset).
"""

from __future__ import annotations

import base64
import time

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view

from .base import PayloadProfile

IMAGE_SHAPE = (3, 32, 32)  # (C, H, W) -- CIFAR-10-shaped
N_CLASSES = 10
_WEIGHT_SEED = 20260609  # arbitrary, fixed for reproducibility
_IMAGE_SEED = 1234


def _conv2d(x: np.ndarray, W: np.ndarray, b: np.ndarray, pad: int = 1) -> np.ndarray:
    """x: (C_in,H,W); W: (C_out,C_in,kh,kw); b: (C_out,). Returns (C_out,H_out,W_out)."""
    C_in, _, _ = x.shape
    C_out, _, kh, kw = W.shape
    x_p = np.pad(x, ((0, 0), (pad, pad), (pad, pad)))
    windows = sliding_window_view(x_p, (C_in, kh, kw))[0]  # (H_out, W_out, C_in, kh, kw)
    H_out, W_out = windows.shape[0], windows.shape[1]
    patches = windows.reshape(H_out * W_out, -1)
    W_mat = W.reshape(C_out, -1)
    out = patches @ W_mat.T + b
    return out.T.reshape(C_out, H_out, W_out)


def _relu(x: np.ndarray) -> np.ndarray:
    return np.maximum(x, 0)


def _maxpool2x2(x: np.ndarray) -> np.ndarray:
    C, H, W = x.shape
    H2, W2 = H - H % 2, W - W % 2
    x = x[:, :H2, :W2]
    return x.reshape(C, H2 // 2, 2, W2 // 2, 2).max(axis=(2, 4))


def _softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - np.max(x))
    return e / e.sum()


class _FixedWeights:
    """Deterministic, untrained weight initialization -- computed once per process."""

    def __init__(self, seed: int = _WEIGHT_SEED) -> None:
        rng = np.random.default_rng(seed)
        self.conv1_W = rng.normal(0, 0.1, size=(8, 3, 3, 3)).astype(np.float32)
        self.conv1_b = np.zeros(8, dtype=np.float32)
        self.conv2_W = rng.normal(0, 0.1, size=(16, 8, 3, 3)).astype(np.float32)
        self.conv2_b = np.zeros(16, dtype=np.float32)
        # 32x32 -> conv1+pool -> 16x16 -> conv2+pool -> 8x8; flatten = 16*8*8 = 1024
        self.fc_W = rng.normal(0, 0.05, size=(N_CLASSES, 16 * 8 * 8)).astype(np.float32)
        self.fc_b = np.zeros(N_CLASSES, dtype=np.float32)


class ImageCNNProfile(PayloadProfile):
    name = "image_cnn"
    description = (
        "32x32x3 image classifier (fixed-weight NumPy CNN, base64-encoded request) -- "
        "large request (~4KB), small response. Represents a vision-classifier endpoint. "
        "Weights are untrained (deterministically seeded); classification accuracy is not "
        "evaluated or claimed -- see docs/DESIGN.md."
    )
    real_inference = True

    def __init__(self) -> None:
        self._weights: _FixedWeights | None = None
        self._rng = np.random.default_rng(_IMAGE_SEED)

    def _get_weights(self) -> _FixedWeights:
        if self._weights is None:
            self._weights = _FixedWeights()
        return self._weights

    def sample_request(self) -> dict:
        # Spatially-correlated synthetic "image" (not white noise), so
        # convolution activations are non-degenerate.
        img = np.clip(self._rng.normal(128, 40, size=IMAGE_SHAPE), 0, 255).astype(np.uint8)
        return {
            "image_base64": base64.b64encode(img.tobytes()).decode("ascii"),
            "shape": list(IMAGE_SHAPE),
        }

    def predict(self, request_body: dict) -> dict:
        weights = self._get_weights()
        t0 = time.perf_counter()

        raw = base64.b64decode(request_body["image_base64"])
        shape = tuple(request_body.get("shape", IMAGE_SHAPE))
        x = np.frombuffer(raw, dtype=np.uint8).reshape(shape).astype(np.float32) / 255.0

        h = _relu(_conv2d(x, weights.conv1_W, weights.conv1_b))
        h = _maxpool2x2(h)
        h = _relu(_conv2d(h, weights.conv2_W, weights.conv2_b))
        h = _maxpool2x2(h)
        logits = weights.fc_W @ h.reshape(-1) + weights.fc_b
        probs = _softmax(logits)

        inference_ms = (time.perf_counter() - t0) * 1000
        return {
            "prediction": int(np.argmax(probs)),
            "probabilities": probs.tolist(),
            "_inference_ms": inference_ms,
        }
