"""Control server -- no cryptographic wrapper at all.

This is the "zero overhead" floor every protected configuration is measured
against (design doc Phase 1 checkpoint). Run with:

    uvicorn api.server:app --port 8000
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from api import model_service
from api.schemas import PredictRequest, PredictResponse


@asynccontextmanager
async def lifespan(_app: FastAPI):
    model_service.warm_up()
    yield


app = FastAPI(title="PQ-Shield Control API (unprotected)", lifespan=lifespan)


@app.get("/healthz")
def healthz():
    return {"status": "ok", "config": "control"}


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    result = model_service.predict(req.input)
    return PredictResponse(prediction=result["prediction"], probabilities=result["probabilities"])
