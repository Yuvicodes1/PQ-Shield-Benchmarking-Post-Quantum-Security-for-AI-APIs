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
from typing import AsyncIterator

import httpx
from sklearn.datasets import load_digits

from api.secure_client import _b64d, _b64e, do_handshake
from crypto.aead import AEADError, aead_decrypt, aead_encrypt
from crypto.registry import get_client_crypto
from crypto.streaming import (
    HashChainClientState,
    verify_buffer_and_sign_final,
    verify_hash_chain_chunk,
    verify_hash_chain_final,
    verify_per_chunk,
)
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


def _flip_middle_byte(raw: bytes) -> bytes:
    """Same tamper convention as threats/mitm_harness.py's
    _tamper_response_body -- flip one bit in the middle of the field --
    applied directly to already-decoded bytes instead of a re-encoded JSON
    body, since the live streaming loop below works with each chunk's
    fields individually as they arrive rather than one whole HTTP body."""
    if not raw:
        return raw
    mutated = bytearray(raw)
    mutated[len(mutated) // 2] ^= 0xFF
    return bytes(mutated)


async def run_streaming_transaction_live(
    base_url: str,
    config_name: str,
    prompt: str,
    strategy: str,
    chunk_size_tokens: int = 5,
    max_tokens: int = 200,
    checkpoint_interval: int | None = None,
    tamper_chunk_index: int | None = None,
    tamper_target: str = "ciphertext",
) -> AsyncIterator[dict]:
    """Async generator counterpart to api/secure_streaming_client.py's
    run_streaming_transaction, for the Live Demo page's streaming panel.

    Instead of returning one flat metrics dict after the whole stream has
    been consumed, this yields one event dict *as each SSE chunk arrives*,
    so the caller (a Streamlit page) can update the UI token-by-token in
    real time rather than only once the transaction is over. It also
    supports the same live tamper-injection pattern as
    run_secure_transaction above -- locally corrupting one target chunk's
    ciphertext or signature bytes before verification, to demonstrate
    detection happening live instead of only in the final summary.

    `tamper_chunk_index`: the 0-based chunk index to corrupt (None = no
    tampering). buffer_and_sign has no intermediate chunks, so any non-None
    value there tampers the single final envelope instead.
    `tamper_target`: "ciphertext" (AEAD layer) or "signature" (signature
    layer) -- ignored for hash_chain's per-chunk events, which carry no
    per-chunk signature to tamper (only "ciphertext" applies there until
    the terminating signed chain hash, which honors both).

    Event shapes:
      {"type": "chunk", "index": int|None, "text": str|None, "tampered": bool,
       "signature_valid": bool|None, "aead_ok": bool|None,
       "in_order": bool|None, "chain_ok_so_far": bool|None}
      {"type": "final", "stream_fully_verified": bool, "tampered": bool}
      {"type": "summary", "metrics": dict}
      {"type": "error", "message": str}
    """
    client_crypto = get_client_crypto(config_name)
    metrics: dict = {
        "config": config_name, "strategy": strategy, "error": None,
        "ttft_ms": None, "total_ms": None, "n_chunks": 0,
        "total_signature_bytes": 0, "total_signing_ms": 0.0, "total_verify_ms": 0.0,
        "all_signatures_valid": True, "all_aead_ok": True, "all_in_order": True,
        "stream_fully_verified": None, "reconstructed_bytes": 0,
    }

    def _maybe_tamper(index: int | None, field_bytes: bytes, field: str) -> tuple[bytes, bool]:
        if tamper_chunk_index is None or field != tamper_target:
            return field_bytes, False
        if index is None or index == tamper_chunk_index:
            return _flip_middle_byte(field_bytes), True
        return field_bytes, False

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            handshake_json, handshake_ms = await do_handshake(client, base_url)
            metrics["handshake_ms"] = handshake_ms

            kex_public_key = _b64d(handshake_json["kex_public_key"])
            sig_public_key = _b64d(handshake_json["sig_public_key"])
            handshake_id = handshake_json["handshake_id"]

            est = client_crypto.establish(kex_public_key)
            request_body = {
                "prompt": prompt, "strategy": strategy,
                "chunk_size_tokens": chunk_size_tokens, "max_tokens": max_tokens,
            }
            if checkpoint_interval is not None:
                request_body["checkpoint_interval"] = checkpoint_interval

            request_plaintext = json.dumps(request_body).encode()
            req_aead = aead_encrypt(est.session_key, request_plaintext)
            payload = {
                "handshake_id": handshake_id,
                "kex_blob": _b64e(est.kex_blob),
                "nonce": _b64e(req_aead.nonce),
                "ciphertext": _b64e(req_aead.ciphertext),
            }

            t_start = time.perf_counter()
            chain_state = HashChainClientState() if strategy == "hash_chain" else None
            expected_index = 0
            reconstructed = bytearray()

            async with client.stream("POST", f"{base_url}/secure/predict/stream", json=payload) as resp:
                if resp.status_code != 200:
                    body = await resp.aread()
                    yield {"type": "error", "message": f"HTTP {resp.status_code}: {body[:200]}"}
                    return

                async for line in resp.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    data = json.loads(line[len("data:"):].strip())

                    if metrics["ttft_ms"] is None:
                        metrics["ttft_ms"] = (time.perf_counter() - t_start) * 1000

                    kind = data.get("kind")

                    if kind == "chunk" and strategy == "per_chunk":
                        ciphertext, ct_tampered = _maybe_tamper(
                            data["index"], _b64d(data["ciphertext"]), "ciphertext"
                        )
                        signature, sig_tampered = _maybe_tamper(
                            data["index"], _b64d(data["signature"]), "signature"
                        )
                        chunk = {
                            "index": data["index"], "nonce": _b64d(data["nonce"]),
                            "ciphertext": ciphertext, "signature": signature,
                        }
                        result = verify_per_chunk(chunk, expected_index, est.session_key,
                                                   sig_public_key, client_crypto)
                        metrics["all_signatures_valid"] &= result["signature_valid"]
                        metrics["all_aead_ok"] &= bool(result["aead_ok"])
                        metrics["all_in_order"] &= result["in_order"]
                        metrics["total_signature_bytes"] += data.get("signature_bytes", 0)
                        metrics["total_verify_ms"] += result["verify_ms"]
                        metrics["total_signing_ms"] += data.get("sign_ms", 0.0)
                        metrics["n_chunks"] += 1
                        expected_index += 1
                        text = None
                        if result["plaintext"]:
                            reconstructed.extend(result["plaintext"])
                            text = result["plaintext"].decode(errors="replace")
                        yield {
                            "type": "chunk", "index": data["index"], "text": text,
                            "tampered": ct_tampered or sig_tampered,
                            "signature_valid": result["signature_valid"],
                            "aead_ok": result["aead_ok"], "in_order": result["in_order"],
                            "chain_ok_so_far": None,
                        }

                    elif kind == "chunk" and strategy == "hash_chain":
                        ciphertext, ct_tampered = _maybe_tamper(
                            data["index"], _b64d(data["ciphertext"]), "ciphertext"
                        )
                        chunk = {
                            "index": data["index"], "nonce": _b64d(data["nonce"]),
                            "ciphertext": ciphertext, "chain_hash": _b64d(data["chain_hash"]),
                        }
                        result = verify_hash_chain_chunk(chunk, chain_state, est.session_key)
                        metrics["all_aead_ok"] &= bool(result["aead_ok"])
                        metrics["total_signature_bytes"] += data.get("signature_bytes", 0)
                        metrics["total_signing_ms"] += data.get("sign_ms", 0.0)
                        metrics["n_chunks"] += 1
                        text = None
                        if result["plaintext"]:
                            reconstructed.extend(result["plaintext"])
                            text = result["plaintext"].decode(errors="replace")
                        yield {
                            "type": "chunk", "index": data["index"], "text": text,
                            "tampered": ct_tampered,
                            "signature_valid": None, "aead_ok": result["aead_ok"],
                            "in_order": None, "chain_ok_so_far": result["chain_ok_so_far"],
                        }

                    elif kind == "final_buffered":
                        ciphertext, ct_tampered = _maybe_tamper(None, _b64d(data["ciphertext"]), "ciphertext")
                        signature, sig_tampered = _maybe_tamper(None, _b64d(data["signature"]), "signature")
                        final_chunk = {
                            "nonce": _b64d(data["nonce"]), "ciphertext": ciphertext, "signature": signature,
                        }
                        result = verify_buffer_and_sign_final(final_chunk, est.session_key,
                                                                sig_public_key, client_crypto)
                        metrics["all_signatures_valid"] &= result["signature_valid"]
                        metrics["all_aead_ok"] &= bool(result["aead_ok"])
                        metrics["total_signature_bytes"] += data.get("signature_bytes", 0)
                        metrics["total_verify_ms"] += result["verify_ms"]
                        metrics["total_signing_ms"] += data.get("sign_ms", 0.0)
                        if result["plaintext"]:
                            reconstructed.extend(result["plaintext"])
                        metrics["stream_fully_verified"] = (
                            result["signature_valid"] and bool(result["aead_ok"])
                        )
                        yield {
                            "type": "final",
                            "stream_fully_verified": metrics["stream_fully_verified"],
                            "tampered": ct_tampered or sig_tampered,
                            "text": result["plaintext"].decode(errors="replace") if result["plaintext"] else None,
                        }

                    elif kind == "final_chain":
                        signature, sig_tampered = _maybe_tamper(None, _b64d(data["signature"]), "signature")
                        final_chunk = {
                            "final_chain_hash": _b64d(data["final_chain_hash"]), "signature": signature,
                        }
                        result = verify_hash_chain_final(final_chunk, chain_state, sig_public_key, client_crypto)
                        metrics["stream_fully_verified"] = result["stream_fully_verified"]
                        metrics["total_signature_bytes"] += data.get("signature_bytes", 0)
                        metrics["total_verify_ms"] += result["verify_ms"]
                        metrics["total_signing_ms"] += data.get("sign_ms", 0.0)
                        yield {
                            "type": "final",
                            "stream_fully_verified": result["stream_fully_verified"],
                            "tampered": sig_tampered,
                            "text": None,
                        }

            metrics["total_ms"] = (time.perf_counter() - t_start) * 1000
            metrics["reconstructed_bytes"] = len(reconstructed)
            if metrics["stream_fully_verified"] is None:
                metrics["stream_fully_verified"] = (
                    metrics["all_signatures_valid"] and metrics["all_aead_ok"] and metrics["all_in_order"]
                )

        yield {"type": "summary", "metrics": metrics}

    except Exception as exc:
        yield {"type": "error", "message": f"{type(exc).__name__}: {exc}"}
