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
from dataclasses import dataclass
import time

import httpx

from crypto.aead import AEADError, aead_decrypt, aead_encrypt
from crypto.handshake_auth import verify_handshake
from crypto.registry import get_client_crypto


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


@dataclass
class ClientSession:
    """Session resumption state for one client: the first request of a
    session performs the full handshake + key establishment and asks the
    server to keep the session (keep_session=True); the next
    `requests_left - 1` requests reuse the session key with no key exchange at
    all; the last one sends keep_session=False so the server forgets it.
    This is the amortized case a TLS deployment reusing connections sees --
    the counterpart to the default, worst-case one-exchange-per-request."""

    requests_left: int
    handshake_json: dict | None = None
    session_key: bytes | None = None


async def do_handshake(client: httpx.AsyncClient, base_url: str) -> tuple[dict, float]:
    t0 = time.perf_counter()
    resp = await client.get(f"{base_url}/secure/handshake")
    resp.raise_for_status()
    handshake_ms = (time.perf_counter() - t0) * 1000
    return resp.json(), handshake_ms


async def fetch_identity(client: httpx.AsyncClient, base_url: str) -> dict:
    """Pins the server's identity key (authenticated-handshake mode). Fetched
    once, before any measured transaction -- the stand-in for a certificate
    the client already trusts."""
    resp = await client.get(f"{base_url}/secure/identity")
    resp.raise_for_status()
    j = resp.json()
    return {"algorithm": j["algorithm"], "public_key": _b64d(j["public_key"])}


async def secure_predict_transaction(
    client: httpx.AsyncClient,
    base_url: str,
    config_name: str,
    request_body: dict,
    debug_metrics: bool = False,
    cached_handshake: dict | None = None,
    session: ClientSession | None = None,
    pinned_identity: dict | None = None,
) -> dict:
    """Performs one full protected transaction. Returns a flat result/metrics dict.

    `request_body` is a JSON-serializable dict matching whatever payload
    profile the server is currently configured for (model/profiles/*) --
    the protocol layer itself does not know or care about payload shape.

    If `cached_handshake` is provided (the dict returned by do_handshake's
    response .json()), the GET /secure/handshake round trip is skipped --
    this is the "warm connection" variant referenced in api/secure_app.py.

    If `session` is provided, the transaction takes part in session
    resumption (see ClientSession); `session` is updated in place.
    """
    client_crypto = get_client_crypto(config_name)
    row: dict = {"config": config_name, "error": None, "valid_signature": None}

    try:
        resumed = session is not None and session.session_key is not None
        if resumed:
            handshake_json = session.handshake_json
            handshake_ms = 0.0
        elif cached_handshake is not None:
            handshake_json = cached_handshake
            handshake_ms = 0.0
        else:
            handshake_json, handshake_ms = await do_handshake(client, base_url)
        row["resumed"] = resumed
        if pinned_identity is not None and not resumed:
            # The handshake leg includes checking the transcript signature,
            # as a TLS client's handshake includes CertificateVerify.
            ok, auth_meta = verify_handshake(handshake_json, pinned_identity, _b64d)
            handshake_ms += auth_meta["verify_ms"]
            row["handshake_auth_verify_ms"] = auth_meta["verify_ms"]
            if not ok:
                row["handshake_ms"] = handshake_ms
                row["error"] = "handshake authentication failed (transcript signature invalid)"
                return row
        row["handshake_ms"] = handshake_ms

        sig_public_key = _b64d(handshake_json["sig_public_key"])
        handshake_id = handshake_json["handshake_id"]

        if resumed:
            session_key, kex_blob = session.session_key, b""
            row["client_establish_ms"] = 0.0
        else:
            est = client_crypto.establish(_b64d(handshake_json["kex_public_key"]))
            session_key, kex_blob = est.session_key, est.kex_blob
            row["client_establish_ms"] = est.meta.get("handshake_encrypt_ms", 0.0)
            if session is not None:
                session.handshake_json, session.session_key = handshake_json, session_key
        row["kex_blob_bytes"] = len(kex_blob)
        keep_session = session is not None and session.requests_left > 1
        if session is not None:
            session.requests_left -= 1

        request_plaintext = json.dumps(request_body).encode()
        row["request_plaintext_bytes"] = len(request_plaintext)
        req_aead = aead_encrypt(session_key, request_plaintext)

        payload = {
            "handshake_id": handshake_id,
            "keep_session": keep_session,
            "kex_blob": _b64e(kex_blob),
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
        row["signature_bytes"] = len(signature)

        # AEAD first, then signature -- the order the design documents
        # (sequence diagram, threat model): the cheap GCM tag check rejects a
        # tampered ciphertext before the signature is ever verified, and its
        # own timing is what the MITM experiment reports as AEAD-layer
        # detection latency.
        t0 = time.perf_counter()
        try:
            plaintext = aead_decrypt(session_key, resp_nonce, resp_ciphertext)
        except AEADError:
            row["aead_decrypt_ms"] = (time.perf_counter() - t0) * 1000
            row["error"] = "response AEAD authentication failed (tampered response)"
            return row
        row["aead_decrypt_ms"] = (time.perf_counter() - t0) * 1000

        valid, verify_meta = client_crypto.verify(envelope, signature, sig_public_key)
        row["valid_signature"] = valid
        row["verify_ms"] = verify_meta.get("verify_ms", 0.0)

        result = json.loads(plaintext)
        row["prediction"] = result.get("prediction")
        row["response_plaintext_bytes"] = len(plaintext)

    except Exception as exc:  # network errors, timeouts, malformed responses, etc.
        row["error"] = f"{type(exc).__name__}: {exc}"

    return row
