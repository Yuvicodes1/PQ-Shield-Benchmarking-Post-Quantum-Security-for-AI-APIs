"""Configuration C protected API: ML-KEM-768 + ML-DSA-65."""

from contextlib import asynccontextmanager
from time import perf_counter

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from api.schemas import PredictRequest
from api.service import get_model, predict
from crypto.config_a_classical import b64, unb64
from crypto.config_c_full_pqc import FullPqcChannel


@asynccontextmanager
async def lifespan(_: FastAPI):
    get_model()
    yield


app = FastAPI(title="PQ-Shield Configuration C", version="0.1.0", lifespan=lifespan)
channel = FullPqcChannel()


class HandshakeResponse(BaseModel):
    kem_public_key: str
    signing_public_key: str
    algorithm: str


class SecureRequest(BaseModel):
    kem_ciphertext: str
    envelope: str


class SecureResponse(BaseModel):
    envelope: str
    signature: str
    crypto_ms: float


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "configuration": "C-full-pqc"}


@app.get("/secure/handshake", response_model=HandshakeResponse)
def handshake() -> HandshakeResponse:
    kem_public_key, signing_public_key = channel.handshake()
    return HandshakeResponse(
        kem_public_key=b64(kem_public_key),
        signing_public_key=b64(signing_public_key),
        algorithm=channel.algorithm,
    )


@app.post("/secure/predict", response_model=SecureResponse)
def secure_predict(request: SecureRequest) -> SecureResponse:
    started = perf_counter()
    try:
        plaintext, session_key = channel.decrypt_request_with_key(
            unb64(request.kem_ciphertext), unb64(request.envelope)
        )
        payload = PredictRequest.model_validate_json(plaintext)
        result = predict(payload.input).model_dump_json().encode()
        encrypted_response, signature = channel.encrypt_and_sign_response(result, session_key)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid protected request") from exc
    return SecureResponse(
        envelope=b64(encrypted_response), signature=b64(signature),
        crypto_ms=(perf_counter() - started) * 1000,
    )
