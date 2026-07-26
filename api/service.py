"""Shared inference logic. Crypto wrappers must not change this control path."""

from pathlib import Path
from time import perf_counter

import joblib
import numpy as np

from api.schemas import PredictResponse

ARTIFACT = Path(__file__).parents[1] / "model" / "artifacts" / "model.pkl"
_model = None


def get_model():
    global _model
    if _model is None:
        if not ARTIFACT.exists():
            raise RuntimeError("Model artifact is absent. Run `python -m model.train` first.")
        _model = joblib.load(ARTIFACT)
    return _model


def predict(features: list[float]) -> PredictResponse:
    """Return the same inference result regardless of protection configuration."""
    matrix = np.asarray(features, dtype=float).reshape(1, 64)
    started = perf_counter()
    model = get_model()
    prediction = int(model.predict(matrix)[0])
    probabilities = [float(x) for x in model.predict_proba(matrix)[0]]
    return PredictResponse(
        prediction=prediction,
        probabilities=probabilities,
        inference_ms=(perf_counter() - started) * 1000,
    )
