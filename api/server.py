"""Control endpoint plus the secure-classical routes used by the benchmark client."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.schemas import PredictRequest, PredictResponse
from api.service import get_model, predict
from api.server_config_a import (
    HandshakeResponse,
    SecureRequest,
    SecureResponse,
    handshake as secure_handshake_impl,
    secure_predict as secure_predict_impl,
)

@asynccontextmanager
async def lifespan(_: FastAPI):
    # Keep model deserialization out of recorded request timings.
    get_model()
    yield


app = FastAPI(title="PQ-Shield control API", version="0.1.0", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "configuration": "control"}


@app.post("/predict", response_model=PredictResponse)
def predict_endpoint(request: PredictRequest) -> PredictResponse:
    return predict(request.input)


@app.get("/secure/handshake", response_model=HandshakeResponse)
def secure_handshake() -> HandshakeResponse:
    return secure_handshake_impl()


@app.post("/secure/predict", response_model=SecureResponse)
def secure_predict(request: SecureRequest) -> SecureResponse:
    return secure_predict_impl(request)
