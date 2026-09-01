"""Client-side counterpart to api/secure_app.py's /secure/predict/stream.

Performs the same handshake + establish as api/secure_client.py's
non-streaming transaction, then consumes the SSE response and applies
whichever verification logic matches the chosen strategy
(crypto/streaming.py). Returns a flat metrics dict suitable for a CSV row,
mirroring api/secure_client.py's non-streaming return shape where the two
overlap (config, handshake_ms, error) and adding streaming-specific fields
(ttft_ms, n_chunks, total_signature_bytes, all_valid, in_order fields, etc).
"""

from __future__ import annotations

import json
import time

import httpx

from api.secure_client import _b64d, _b64e, do_handshake
from crypto.aead import aead_encrypt
from crypto.registry import get_client_crypto
from crypto.streaming import (
    HashChainClientState,
    verify_buffer_and_sign_final,
    verify_hash_chain_chunk,
    verify_hash_chain_final,
    verify_per_chunk,
)


async def run_streaming_transaction(
    client: httpx.AsyncClient,
    base_url: str,
    config_name: str,
    prompt: str,
    strategy: str,
    chunk_size_tokens: int = 5,
    max_tokens: int = 200,
    checkpoint_interval: int | None = None,
) -> dict:
    """Runs one full streaming transaction and returns a metrics dict.

    `strategy` must be one of crypto.streaming.STRATEGY_NAMES
    ("buffer_and_sign", "per_chunk", "hash_chain").
    """
    client_crypto = get_client_crypto(config_name)
    metrics: dict = {
        "config": config_name,
        "strategy": strategy,
        "chunk_size_tokens": chunk_size_tokens,
        "max_tokens": max_tokens,
        "error": None,
        "ttft_ms": None,
        "total_ms": None,
        "n_chunks": 0,
        "total_signature_bytes": 0,
        "total_signing_ms": 0.0,
        "total_verify_ms": 0.0,
        "all_signatures_valid": True,
        "all_aead_ok": True,
        "all_in_order": True,
        "stream_fully_verified": None,
        "reconstructed_bytes": 0,
    }

    try:
        handshake_json, handshake_ms = await do_handshake(client, base_url)
        metrics["handshake_ms"] = handshake_ms

        kex_public_key = _b64d(handshake_json["kex_public_key"])
        sig_public_key = _b64d(handshake_json["sig_public_key"])
        handshake_id = handshake_json["handshake_id"]

        est = client_crypto.establish(kex_public_key)
        request_body = {
            "prompt": prompt,
            "strategy": strategy,
            "chunk_size_tokens": chunk_size_tokens,
            "max_tokens": max_tokens,
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

        async with client.stream("POST", f"{base_url}/secure/predict/stream", json=payload,
                                  timeout=120.0) as resp:
            if resp.status_code != 200:
                body = await resp.aread()
                metrics["error"] = f"HTTP {resp.status_code}: {body[:200]}"
                return metrics

            async for line in resp.aiter_lines():
                if not line.startswith("data:"):
                    continue
                data = json.loads(line[len("data:"):].strip())

                if metrics["ttft_ms"] is None:
                    metrics["ttft_ms"] = (time.perf_counter() - t_start) * 1000

                kind = data.get("kind")

                if kind == "chunk" and strategy == "per_chunk":
                    chunk = {
                        "index": data["index"],
                        "nonce": _b64d(data["nonce"]),
                        "ciphertext": _b64d(data["ciphertext"]),
                        "signature": _b64d(data["signature"]),
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
                    if result["plaintext"]:
                        reconstructed.extend(result["plaintext"])

                elif kind == "chunk" and strategy == "hash_chain":
                    chunk = {
                        "index": data["index"],
                        "nonce": _b64d(data["nonce"]),
                        "ciphertext": _b64d(data["ciphertext"]),
                        "chain_hash": _b64d(data["chain_hash"]),
                    }
                    result = verify_hash_chain_chunk(chunk, chain_state, est.session_key)
                    metrics["all_aead_ok"] &= bool(result["aead_ok"])
                    metrics["total_signature_bytes"] += data.get("signature_bytes", 0)
                    metrics["total_signing_ms"] += data.get("sign_ms", 0.0)
                    metrics["n_chunks"] += 1
                    if result["plaintext"]:
                        reconstructed.extend(result["plaintext"])

                elif kind == "final_buffered":
                    final_chunk = {
                        "nonce": _b64d(data["nonce"]),
                        "ciphertext": _b64d(data["ciphertext"]),
                        "signature": _b64d(data["signature"]),
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

                elif kind == "final_chain":
                    final_chunk = {
                        "final_chain_hash": _b64d(data["final_chain_hash"]),
                        "signature": _b64d(data["signature"]),
                    }
                    result = verify_hash_chain_final(final_chunk, chain_state, sig_public_key, client_crypto)
                    metrics["stream_fully_verified"] = result["stream_fully_verified"]
                    metrics["total_signature_bytes"] += data.get("signature_bytes", 0)
                    metrics["total_verify_ms"] += result["verify_ms"]
                    metrics["total_signing_ms"] += data.get("sign_ms", 0.0)

        metrics["total_ms"] = (time.perf_counter() - t_start) * 1000
        metrics["reconstructed_bytes"] = len(reconstructed)
        if metrics["stream_fully_verified"] is None:
            # buffer_and_sign / per_chunk: "fully verified" = every check passed,
            # since there's no separate terminating chain check for them.
            metrics["stream_fully_verified"] = (
                metrics["all_signatures_valid"] and metrics["all_aead_ok"] and metrics["all_in_order"]
            )

    except Exception as exc:
        metrics["error"] = f"{type(exc).__name__}: {exc}"

    return metrics
