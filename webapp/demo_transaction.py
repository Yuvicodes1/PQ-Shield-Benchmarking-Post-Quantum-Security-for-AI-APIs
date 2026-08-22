"""Transaction logic for the Streamlit "Live Demo" and "Threat Scenarios"
pages. Reuses the exact same crypto and client code as the CLI clients
(api/secure_client.py) and the CLI tests, plus threats/mitm_harness.py's
tamper function, so a demo request runs through identical code paths to
the paper's actual benchmark and threat scripts -- the only difference is
where the client-side tamper injection happens (locally, before
decrypt/verify, rather than via a separate proxy process), which keeps the
live demo self-contained without needing to manage a third subprocess.
"""

from __future__ import annotations

import json
import time

import httpx
from sklearn.datasets import load_digits

from api.secure_client import _b64d, _b64e, do_handshake
from crypto.aead import AEADError, aead_decrypt, aead_encrypt
from crypto.registry import get_client_crypto
from threats.mitm_harness import _tamper_response_body

_DIGITS = load_digits()


def n_samples() -> int:
    return len(_DIGITS.data)


def get_sample(index: int) -> tuple[list[float], "object", int]:
    """Returns (features, 8x8 image array, true label) for a UCI digits test sample."""
    features = _DIGITS.data[index].tolist()
    image = _DIGITS.images[index]
    label = int(_DIGITS.target[index])
    return features, image, label


async def run_control_transaction(base_url: str, features: list[float]) -> dict:
    row: dict = {"config": "control", "error": None, "tampered": None}
    async with httpx.AsyncClient(timeout=15.0) as client:
        t0 = time.perf_counter()
        try:
            resp = await client.post(f"{base_url}/predict", json={"input": features})
            row["rtt_ms"] = (time.perf_counter() - t0) * 1000
            if resp.status_code == 200:
                body = resp.json()
                row["prediction"] = body["prediction"]
                row["probabilities"] = body["probabilities"]
            else:
                row["error"] = f"HTTP {resp.status_code}"
        except Exception as exc:
            row["error"] = f"{type(exc).__name__}: {exc}"
    return row


async def run_secure_transaction(
    base_url: str,
    config_name: str,
    features: list[float],
    tamper_target: str | None = None,
) -> dict:
    """Full protected transaction: handshake -> establish -> AEAD-encrypt
    request -> POST -> (optionally tamper the raw response bytes locally,
    exactly as threats/mitm_harness.py's proxy would) -> AEAD-decrypt ->
    verify signature.

    tamper_target: None (no tampering), "ciphertext", or "signature".
    """
    client_crypto = get_client_crypto(config_name)
    row: dict = {
        "config": config_name,
        "error": None,
        "valid_signature": None,
        "tampered": tamper_target,
        "decryption_ok": None,
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            handshake_json, handshake_ms = await do_handshake(client, base_url)
            row["handshake_ms"] = handshake_ms
            row["handshake_meta"] = handshake_json.get("meta", {})
            row["kex_algorithm"] = handshake_json.get("kex_algorithm")
            row["sig_algorithm"] = handshake_json.get("sig_algorithm")

            kex_public_key = _b64d(handshake_json["kex_public_key"])
            sig_public_key = _b64d(handshake_json["sig_public_key"])
            handshake_id = handshake_json["handshake_id"]

            est = client_crypto.establish(kex_public_key)
            row["client_establish_ms"] = est.meta.get("handshake_encrypt_ms", 0.0)
            row["kex_blob_bytes"] = len(est.kex_blob)

            request_plaintext = json.dumps({"input": features}).encode()
            req_aead = aead_encrypt(est.session_key, request_plaintext)

            payload = {
                "handshake_id": handshake_id,
                "kex_blob": _b64e(est.kex_blob),
                "nonce": _b64e(req_aead.nonce),
                "ciphertext": _b64e(req_aead.ciphertext),
            }

            t0 = time.perf_counter()
            resp = await client.post(
                f"{base_url}/secure/predict", json=payload, headers={"X-Debug-Metrics": "true"}
            )
            row["rtt_ms"] = (time.perf_counter() - t0) * 1000

            if resp.status_code != 200:
                row["error"] = f"HTTP {resp.status_code}: {resp.text[:200]}"
                return row

            raw_body = resp.content
            if tamper_target:
                raw_body = _tamper_response_body(raw_body, tamper_target)
            resp_json = json.loads(raw_body)

            row["server_timing_ms"] = resp_json.get("server_timing_ms", {})
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
                row["probabilities"] = result.get("probabilities")
                row["decryption_ok"] = True
            except AEADError:
                row["decryption_ok"] = False
                row["error"] = "AES-GCM authentication failed -- tampered ciphertext detected and rejected"

        except Exception as exc:
            row["error"] = f"{type(exc).__name__}: {exc}"

    return row
