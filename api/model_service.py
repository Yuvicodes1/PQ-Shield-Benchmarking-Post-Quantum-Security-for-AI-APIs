"""Loads the serialized RandomForest model once per process and exposes a
single `predict` call. Shared by the control server and all three protected
configurations so inference logic is identical across every benchmark arm --
the crypto wrapper is the only thing that differs between server processes.
"""

from __future__ import annotations

import os
import time

import joblib
import numpy as np

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "model", "artifacts", "model.pkl"
)

_model = None


def _get_model():
    global _model
    if _model is None:
        if not os.path.isfile(MODEL_PATH):
            raise RuntimeError(
                f"Model artifact not found at {MODEL_PATH}. Run `python -m model.train` first."
            )
        _model = joblib.load(MODEL_PATH)
    return _model


def predict(features: list[float]) -> dict:
    """Runs inference and returns the response payload plus server-side timing."""
    model = _get_model()
    t0 = time.perf_counter()
    x = np.array(features, dtype=float).reshape(1, -1)
    pred = int(model.predict(x)[0])
    proba = model.predict_proba(x)[0].tolist()
    inference_ms = (time.perf_counter() - t0) * 1000
    return {
        "prediction": pred,
        "probabilities": proba,
        "_inference_ms": inference_ms,
    }


def warm_up() -> None:
    """Loads the model and runs one dummy prediction at server startup."""
    predict([0.0] * 64)
