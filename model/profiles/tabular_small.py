"""Payload profile: tabular_small.

64-feature handwritten-digit classifier (100-tree RandomForest, real
trained model, see model/train.py). Small request (~345B), small response
(~93B). Represents a diagnostic/IoT-style classifier endpoint -- the
profile every other profile in this project is compared against.
"""

from __future__ import annotations

import os
import time

import joblib
import numpy as np
from sklearn.datasets import load_digits

from .base import PayloadProfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_PATH = os.path.join(_REPO_ROOT, "model", "artifacts", "model.pkl")


class TabularSmallProfile(PayloadProfile):
    name = "tabular_small"
    description = (
        "64-feature handwritten-digit classifier (RandomForest, real trained model) -- "
        "small request, small response. Represents a diagnostic/IoT-style classifier endpoint."
    )
    real_inference = True

    def __init__(self) -> None:
        self._model = None
        self._digits = load_digits()

    def _get_model(self):
        if self._model is None:
            if not os.path.isfile(MODEL_PATH):
                raise RuntimeError(
                    f"Model artifact not found at {MODEL_PATH}. Run `python -m model.train` first."
                )
            self._model = joblib.load(MODEL_PATH)
        return self._model

    def sample_request(self) -> dict:
        idx = np.random.randint(0, len(self._digits.data))
        return {"input": self._digits.data[idx].tolist()}

    def predict(self, request_body: dict) -> dict:
        model = self._get_model()
        t0 = time.perf_counter()
        x = np.array(request_body["input"], dtype=float).reshape(1, -1)
        pred = int(model.predict(x)[0])
        proba = model.predict_proba(x)[0].tolist()
        inference_ms = (time.perf_counter() - t0) * 1000
        return {"prediction": pred, "probabilities": proba, "_inference_ms": inference_ms}
