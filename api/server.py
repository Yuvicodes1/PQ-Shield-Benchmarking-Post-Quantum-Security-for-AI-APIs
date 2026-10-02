"""Control server -- no cryptographic wrapper at all.

This is the "zero overhead" floor every protected configuration is measured
against (design doc Phase 1 checkpoint). Run with:

    uvicorn api.server:app --port 8000

Accepts a generic JSON body on /predict, dispatched to whichever payload
profile is active (PQ_SHIELD_PAYLOAD_PROFILE env var) -- request/response
shape varies by profile, so this endpoint no longer enforces a fixed
pydantic schema.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Body, FastAPI

from api import model_service


@asynccontextmanager
async def lifespan(_app: FastAPI):
    model_service.warm_up()
    yield


app = FastAPI(title="PQ-Shield Control API (unprotected)", lifespan=lifespan)


@app.get("/healthz")
def healthz():
    return {
        "status": "ok",
        "config": "control",
        "payload_profile": model_service.active_profile_name(),
    }


@app.post("/predict")
def predict(body: dict = Body(...)):
    # Plain `def`, like the protected /secure/predict: FastAPI runs it in its
    # worker thread pool. It used to be `async def` calling the blocking model
    # directly on the event loop, which serialized every request and stopped
    # the server accepting connections under load (52-66% ConnectErrors at
    # 1,000 connections in sweep 20261002T125818) -- a handicap only the
    # baseline had, which biased every overhead-vs-control number.
    result = model_service.predict(body)
    result.pop("_inference_ms", None)
    return result
