"""Builds the protected FastAPI app for a given crypto configuration.

Exposes:
  GET  /secure/handshake  -> fresh ephemeral key pair bundle (base64 JSON)
  POST /secure/predict    -> AES-256-GCM encrypted + signed prediction

server_config_a.py / server_config_b.py / server_config_c.py are thin
wrappers around this factory (config_name="classical" / "hybrid" / "full_pqc")
so `uvicorn api.server_config_a:app` etc. keep working exactly as documented
in the README, while the actual endpoint logic is written once.

Design choices called out explicitly (see docs/DESIGN.md):
  - A fresh handshake is generated on every /secure/handshake call, and the
    default benchmark protocol performs one handshake per predict
    transaction. This is the conservative, worst-case measurement; a
    "warm connection" (reused handshake) variant can be benchmarked
    separately by calling /secure/handshake once and re-using handshake_id
    for many /secure/predict calls (see bench/runner.py --reuse-handshake).
  - `server_timing_ms` is always returned (needed for every RTT/handshake
    benchmark row); the byte-size breakdown used only by the HNDL threat
    script is gated behind the `X-Debug-Metrics: true` request header so
    production-shaped responses stay realistic by default.
"""

from __future__ import annotations

import base64
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException

from api import model_service
from api.schemas import (
    HandshakeResponse,
    SecurePredictRequest,
    SecurePredictResponse,
)
from crypto.aead import AEADError, aead_decrypt, aead_encrypt
from crypto.registry import get_server_crypto


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def build_app(config_name: str) -> FastAPI:
    server_crypto = get_server_crypto(config_name)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        model_service.warm_up()
        yield

    app = FastAPI(title=f"PQ-Shield Secure API [{config_name}]", lifespan=lifespan)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "config": config_name}

    @app.get("/secure/handshake", response_model=HandshakeResponse)
    def handshake():
        bundle = server_crypto.new_handshake()
        return HandshakeResponse(
            handshake_id=bundle.handshake_id,
            kex_public_key=_b64e(bundle.kex_public_key),
            sig_public_key=_b64e(bundle.sig_public_key),
            kex_algorithm=server_crypto.kex_algorithm,
            sig_algorithm=server_crypto.sig_algorithm,
            meta=bundle.meta,
        )

    @app.post("/secure/predict", response_model=SecurePredictResponse)
    def secure_predict(req: SecurePredictRequest, x_debug_metrics: str | None = Header(default=None)):
        t_total_start = time.perf_counter()
        debug_wanted = (x_debug_metrics or "").lower() == "true"

        try:
            kex_blob = _b64d(req.kex_blob)
            req_nonce = _b64d(req.nonce)
            req_ciphertext = _b64d(req.ciphertext)
        except Exception:
            raise HTTPException(status_code=400, detail="Malformed base64 in request")

        try:
            session_key, accept_meta = server_crypto.accept(req.handshake_id, kex_blob)
        except KeyError:
            raise HTTPException(status_code=404, detail="Unknown or expired handshake_id")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Key establishment failed: {exc}")

        try:
            plaintext = aead_decrypt(session_key, req_nonce, req_ciphertext)
        except AEADError:
            raise HTTPException(status_code=400, detail="Request payload failed authentication")

        import json

        body = json.loads(plaintext)
        result = model_service.predict(body["input"])
        inference_ms = result.pop("_inference_ms")

        response_plaintext = json.dumps(
            {"prediction": result["prediction"], "probabilities": result["probabilities"]}
        ).encode()

        t_encrypt = time.perf_counter()
        resp_aead = aead_encrypt(session_key, response_plaintext)
        encrypt_ms = (time.perf_counter() - t_encrypt) * 1000

        envelope = resp_aead.nonce + resp_aead.ciphertext
        signature, sign_meta = server_crypto.sign(req.handshake_id, envelope)

        server_crypto.forget(req.handshake_id)

        total_ms = (time.perf_counter() - t_total_start) * 1000
        timing = {
            "decapsulate_ms": accept_meta.get("decapsulate_ms", 0.0),
            "inference_ms": inference_ms,
            "encrypt_ms": encrypt_ms,
            "sign_ms": sign_meta.get("sign_ms", 0.0),
            "server_crypto_ms": accept_meta.get("decapsulate_ms", 0.0)
            + encrypt_ms
            + sign_meta.get("sign_ms", 0.0),
            "server_total_ms": total_ms,
        }

        debug = None
        if debug_wanted:
            debug = {
                "kex_blob_bytes": accept_meta.get("kex_blob_bytes"),
                "response_ciphertext_bytes": len(resp_aead.ciphertext),
                "signature_bytes": sign_meta.get("signature_bytes"),
                "kex_algorithm": server_crypto.kex_algorithm,
                "sig_algorithm": server_crypto.sig_algorithm,
            }

        return SecurePredictResponse(
            nonce=_b64e(resp_aead.nonce),
            ciphertext=_b64e(resp_aead.ciphertext),
            signature=_b64e(signature),
            server_timing_ms=timing,
            debug=debug,
        )

    return app
