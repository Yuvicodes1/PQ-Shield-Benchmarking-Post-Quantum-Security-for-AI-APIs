"""Configuration A protected API. Keep `api.server` unchanged as control."""

import json
from contextlib import asynccontextmanager
from time import perf_counter

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from api.schemas import PredictRequest
from api.service import get_model, predict
from crypto.config_a_classical import ClassicalChannel, b64, unb64

@asynccontextmanager
async def lifespan(_: FastAPI):
    # Keep model deserialization out of recorded request timings.
    get_model()
    yield


app = FastAPI(title="PQ-Shield Configuration A", version="0.1.0", lifespan=lifespan)
channel = ClassicalChannel()


class HandshakeResponse(BaseModel):
    key_exchange_public_key: str
    signing_public_key: str
    algorithm: str


class SecureRequest(BaseModel):
    encrypted_key: str
    envelope: str


class SecureResponse(BaseModel):
    envelope: str
    signature: str
    crypto_ms: float


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "configuration": "A-classical"}


@app.get("/secure/handshake", response_model=HandshakeResponse)
def handshake() -> HandshakeResponse:
    return HandshakeResponse(**channel.handshake().__dict__)


@app.post("/secure/predict", response_model=SecureResponse)
def secure_predict(request: SecureRequest) -> SecureResponse:
    started = perf_counter()
    try:
        plaintext, session_key = channel.decrypt_request_with_key(
            unb64(request.encrypted_key), unb64(request.envelope)
        )
        payload = PredictRequest.model_validate_json(plaintext)
        result = predict(payload.input).model_dump_json().encode()
        encrypted_response, signature = channel.encrypt_and_sign_response(result, session_key)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid protected request") from exc
    return SecureResponse(
        envelope=b64(encrypted_response),
        signature=b64(signature),
        crypto_ms=(perf_counter() - started) * 1000,
    )
