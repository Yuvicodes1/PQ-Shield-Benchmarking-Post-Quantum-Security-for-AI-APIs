"""Client-side protocol logic shared by the three CLI clients
(client.py / client_hybrid.py / client_full_pqc.py) and bench/runner.py.

A single `secure_predict_transaction()` call performs:
  1. GET  /secure/handshake                (unless a handshake is reused)
  2. establish() a session key locally     (RSA-OAEP encrypt or ML-KEM encaps)
  3. AES-256-GCM encrypt the request body
  4. POST /secure/predict
  5. AES-256-GCM decrypt the response body
  6. verify() the response signature

and returns a flat dict of timings + the decrypted result + validity, which
is exactly one row of `bench/runner.py`'s output schema.
"""

from __future__ import annotations

import base64
import json
import time

import httpx

from crypto.aead import AEADError, aead_decrypt, aead_encrypt
from crypto.registry import get_client_crypto


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


async def do_handshake(client: httpx.AsyncClient, base_url: str) -> tuple[dict, float]:
    t0 = time.perf_counter()
    resp = await client.get(f"{base_url}/secure/handshake")
    resp.raise_for_status()
    handshake_ms = (time.perf_counter() - t0) * 1000
    return resp.json(), handshake_ms


async def secure_predict_transaction(
    client: httpx.AsyncClient,
    base_url: str,
    config_name: str,
    request_body: dict,
    debug_metrics: bool = False,
    cached_handshake: dict | None = None,
) -> dict:
    """Performs one full protected transaction. Returns a flat result/metrics dict.

    `request_body` is a JSON-serializable dict matching whatever payload
    profile the server is currently configured for (model/profiles/*) --
    the protocol layer itself does not know or care about payload shape.

    If `cached_handshake` is provided (the dict returned by do_handshake's
    response .json()), the GET /secure/handshake round trip is skipped --
    this is the "warm connection" variant referenced in api/secure_app.py.
    """
    client_crypto = get_client_crypto(config_name)
    row: dict = {"config": config_name, "error": None, "valid_signature": None}

    try:
        if cached_handshake is not None:
            handshake_json = cached_handshake
            handshake_ms = 0.0
        else:
            handshake_json, handshake_ms = await do_handshake(client, base_url)
        row["handshake_ms"] = handshake_ms

        kex_public_key = _b64d(handshake_json["kex_public_key"])
        sig_public_key = _b64d(handshake_json["sig_public_key"])
        handshake_id = handshake_json["handshake_id"]

        est = client_crypto.establish(kex_public_key)
        row["client_establish_ms"] = est.meta.get("handshake_encrypt_ms", 0.0)
        row["kex_blob_bytes"] = len(est.kex_blob)

        request_plaintext = json.dumps(request_body).encode()
        row["request_plaintext_bytes"] = len(request_plaintext)
        req_aead = aead_encrypt(est.session_key, request_plaintext)

        payload = {
            "handshake_id": handshake_id,
            "kex_blob": _b64e(est.kex_blob),
            "nonce": _b64e(req_aead.nonce),
            "ciphertext": _b64e(req_aead.ciphertext),
        }
        headers = {"X-Debug-Metrics": "true"} if debug_metrics else {}

        t0 = time.perf_counter()
        resp = await client.post(f"{base_url}/secure/predict", json=payload, headers=headers)
        rtt_ms = (time.perf_counter() - t0) * 1000
        row["rtt_ms"] = rtt_ms
        row["total_ms"] = handshake_ms + rtt_ms

        if resp.status_code != 200:
            row["error"] = f"HTTP {resp.status_code}: {resp.text[:200]}"
            return row

        resp_json = resp.json()
        row["server_timing_ms"] = resp_json.get("server_timing_ms", {})
        if debug_metrics:
            row["debug"] = resp_json.get("debug")

        resp_nonce = _b64d(resp_json["nonce"])
        resp_ciphertext = _b64d(resp_json["ciphertext"])
        signature = _b64d(resp_json["signature"])
        envelope = resp_nonce + resp_ciphertext

        valid, verify_meta = client_crypto.verify(envelope, signature, sig_public_key)
        row["valid_signature"] = valid
        row["verify_ms"] = verify_meta.get("verify_ms", 0.0)
        row["signature_bytes"] = len(signature)

        try:
            plaintext = aead_decrypt(est.session_key, resp_nonce, resp_ciphertext)
            result = json.loads(plaintext)
            row["prediction"] = result.get("prediction")
            row["response_plaintext_bytes"] = len(plaintext)
        except AEADError:
            row["error"] = "response AEAD authentication failed (tampered response)"

    except Exception as exc:  # network errors, timeouts, malformed responses, etc.
        row["error"] = f"{type(exc).__name__}: {exc}"

    return row
