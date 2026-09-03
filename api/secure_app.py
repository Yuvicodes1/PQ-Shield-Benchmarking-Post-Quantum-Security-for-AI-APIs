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
import json
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse

from api import model_service
from api.async_bridge import aiter_sync_generator
from api.schemas import (
    HandshakeResponse,
    SecurePredictRequest,
    SecurePredictResponse,
)
from crypto.aead import AEADError, aead_decrypt, aead_encrypt
from crypto.registry import get_server_crypto
from crypto.streaming import get_server_strategy
from model.streaming_backends.registry import get_backend


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
        return {
            "status": "ok",
            "config": config_name,
            "payload_profile": model_service.active_profile_name(),
        }

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

        body = json.loads(plaintext)
        result = model_service.predict(body)
        inference_ms = result.pop("_inference_ms")

        response_plaintext = json.dumps(result).encode()

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

    @app.post("/secure/predict/stream")
    def secure_predict_stream(req: SecurePredictRequest):
        """SSE streaming counterpart to /secure/predict, for payloads that
        do not exist in full at request time (e.g. LLM token generation).

        The initial request/response envelope (handshake_id, kex_blob,
        nonce, ciphertext) is identical in shape to /secure/predict -- only
        the *response* becomes a stream of Server-Sent Events instead of
        one JSON body. The decrypted request plaintext carries the
        streaming-specific parameters (`prompt`, `strategy`,
        `chunk_size_tokens`, `max_tokens`) as ordinary JSON fields, so no
        new request schema is needed; see crypto/streaming.py for what each
        `strategy` name means and api/secure_streaming_client.py for the
        matching client-side consumption logic.

        Each SSE `data:` line is one JSON-encoded chunk dict from
        crypto/streaming.py's server strategies, with any bytes fields
        (nonce, ciphertext, signature, chain_hash) base64-encoded for wire
        transport. A final `event: done` line closes the stream.
        """
        try:
            kex_blob = _b64d(req.kex_blob)
            req_nonce = _b64d(req.nonce)
            req_ciphertext = _b64d(req.ciphertext)
        except Exception:
            raise HTTPException(status_code=400, detail="Malformed base64 in request")

        try:
            session_key, _accept_meta = server_crypto.accept(req.handshake_id, kex_blob)
        except KeyError:
            raise HTTPException(status_code=404, detail="Unknown or expired handshake_id")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Key establishment failed: {exc}")

        try:
            plaintext = aead_decrypt(session_key, req_nonce, req_ciphertext)
        except AEADError:
            raise HTTPException(status_code=400, detail="Request payload failed authentication")

        body = json.loads(plaintext)
        prompt = body.get("prompt", "")
        strategy_name = body.get("strategy", "buffer_and_sign")
        chunk_size_tokens = max(1, int(body.get("chunk_size_tokens", 5)))
        max_tokens = max(1, int(body.get("max_tokens", 200)))
        checkpoint_interval = body.get("checkpoint_interval")  # only used by hash_chain

        try:
            strategy_kwargs = {"checkpoint_interval": checkpoint_interval} if strategy_name == "hash_chain" else {}
            strategy = get_server_strategy(strategy_name, server_crypto, req.handshake_id, session_key,
                                            **strategy_kwargs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        backend = get_backend()

        def _encode_for_wire(d: dict) -> dict:
            out = {}
            for k, v in d.items():
                if isinstance(v, bytes):
                    out[k] = _b64e(v)
                else:
                    out[k] = v
            return out

        async def event_generator():
            index = 0
            token_buffer: list[str] = []
            t_start = time.perf_counter()

            def flush_buffer() -> str | None:
                nonlocal index
                if not token_buffer:
                    return None
                text = "".join(token_buffer)
                token_buffer.clear()
                wire_chunk = strategy.add_chunk(text.encode(), index)
                index += 1
                if wire_chunk is None:
                    return None
                return f"data: {json.dumps(_encode_for_wire(wire_chunk))}\n\n"

            async for token in aiter_sync_generator(backend.stream(prompt, max_tokens)):
                token_buffer.append(token)
                if len(token_buffer) >= chunk_size_tokens:
                    sse_line = flush_buffer()
                    if sse_line:
                        yield sse_line

            trailing = flush_buffer()
            if trailing:
                yield trailing

            final = strategy.finalize(index)
            if final is not None:
                yield f"data: {json.dumps(_encode_for_wire(final))}\n\n"

            total_ms = (time.perf_counter() - t_start) * 1000
            yield f"event: done\ndata: {json.dumps({'n_chunks': index, 'total_ms': total_ms})}\n\n"

            server_crypto.forget(req.handshake_id)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
        )

    return app
