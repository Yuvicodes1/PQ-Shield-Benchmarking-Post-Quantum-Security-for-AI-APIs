"""Transaction logic for the Streamlit "Live Streamer" and "Threat Scenarios"
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
    verify_per_chunk_final,
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


STREAM_ATTACKS = {
    None: "No attack",
    "tamper_ciphertext": "Flip a bit in one chunk's ciphertext",
    "tamper_signature": "Flip a bit in a signature",
    "drop": "Drop one chunk",
    "reorder": "Swap one chunk with the next",
    "duplicate": "Deliver one chunk twice",
    "truncate": "Cut the stream after one chunk",
    "strip_checkpoints": "Strip every checkpoint signature",
}


async def run_streaming_transaction_live(
    base_url: str,
    config_name: str,
    prompt: str,
    strategy: str,
    chunk_size_tokens: int = 5,
    max_tokens: int = 200,
    checkpoint_interval: int | None = None,
    attack: str | None = None,
    attack_index: int = 2,
    enforce_schedule: bool = True,
) -> AsyncIterator[dict]:
    """Live counterpart to api/secure_streaming_client.run_streaming_transaction
    for the Live demo page: yields one event per SSE record as it arrives, so
    the page can render each chunk the moment it is decrypted and show whether
    a verified signature covers it yet.

    `attack` simulates an on-path adversary at chunk `attack_index` (see
    STREAM_ATTACKS): flipping bits, or rearranging validly protected records
    without forging any -- drop, reorder, duplicate, truncate, or stripping
    the checkpoint signatures. Verification uses the same functions as the
    benchmark client, including checkpoint verification and, when
    `enforce_schedule`, the requested checkpoint schedule.

    Events:
      {"type": "chunk", "index", "text", "status": "verified"|"pending"|"rejected",
       "reason": str|None, "attacked": bool, "signature_valid", "aead_ok"}
      {"type": "covered", "upto": int}      -- every chunk so far is now covered by a verified signature
      {"type": "final", "stream_fully_verified": bool, "reason": str|None, "text": str|None}
      {"type": "summary", "metrics": dict}
      {"type": "error", "message": str}
    """
    client_crypto = get_client_crypto(config_name)
    metrics: dict = {
        "config": config_name, "strategy": strategy, "checkpoint_interval": checkpoint_interval,
        "attack": attack, "error": None, "ttft_ms": None, "total_ms": None, "n_chunks": 0, "n_signatures": 0,
        "total_signature_bytes": 0, "total_signing_ms": 0.0, "total_signing_cpu_ms": 0.0,
        "total_verify_ms": 0.0, "stream_fully_verified": None, "max_unverified_chunks": 0,
        "rejected_at_chunk": None,
    }

    def _flip(field: str, data: dict) -> dict:
        return {**data, field: _b64e(_flip_middle_byte(_b64d(data[field])))}

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            handshake_json, handshake_ms = await do_handshake(client, base_url)
            metrics["handshake_ms"] = handshake_ms
            sig_public_key = _b64d(handshake_json["sig_public_key"])
            handshake_id = handshake_json["handshake_id"]
            est = client_crypto.establish(_b64d(handshake_json["kex_public_key"]))
            request_body = {"prompt": prompt, "strategy": strategy,
                            "chunk_size_tokens": chunk_size_tokens, "max_tokens": max_tokens}
            if checkpoint_interval:
                request_body["checkpoint_interval"] = checkpoint_interval
            req_aead = aead_encrypt(est.session_key, json.dumps(request_body).encode())
            payload = {"handshake_id": handshake_id, "kex_blob": _b64e(est.kex_blob),
                       "nonce": _b64e(req_aead.nonce), "ciphertext": _b64e(req_aead.ciphertext)}

            t_start = time.perf_counter()
            chain_state = (HashChainClientState(handshake_id,
                                                checkpoint_interval=checkpoint_interval if enforce_schedule else None)
                           if strategy == "hash_chain" else None)
            state = {"expected": 0, "pending": 0, "failed": None, "terminal": False, "held": None,
                     "signed_seen": 0}

            def account(data: dict) -> None:
                metrics["total_signature_bytes"] += data.get("signature_bytes", 0) or 0
                metrics["total_signing_ms"] += data.get("sign_ms", 0.0) or 0.0
                metrics["total_signing_cpu_ms"] += data.get("sign_cpu_ms", 0.0) or 0.0
                if data.get("signature"):
                    metrics["n_signatures"] += 1

            def fail(reason: str, index) -> None:
                if state["failed"] is None:
                    state["failed"] = reason
                    metrics["rejected_at_chunk"] = index

            def process(data: dict, attacked: bool) -> list[dict]:
                """Verify one record; return the events it produces."""
                kind = data.get("kind")
                out: list[dict] = []
                if kind == "chunk":
                    account(data)
                    metrics["n_chunks"] += 1
                    nonce, ct = _b64d(data["nonce"]), _b64d(data["ciphertext"])
                    if strategy == "per_chunk":
                        r = verify_per_chunk({"index": data["index"], "nonce": nonce, "ciphertext": ct,
                                              "signature": _b64d(data["signature"])}, state["expected"],
                                             est.session_key, sig_public_key, client_crypto, handshake_id)
                        state["expected"] += 1
                        metrics["total_verify_ms"] += r["verify_ms"]
                        ok = r["signature_valid"] and bool(r["aead_ok"]) and r["in_order"]
                        reason = None if ok else ("signature invalid" if not r["signature_valid"] else
                                                  "AEAD tag failed" if r["aead_ok"] is False else
                                                  "out of order")
                        if not ok:
                            fail(reason, data["index"])
                        text = r["plaintext"].decode(errors="replace") if r["plaintext"] else None
                        out.append({"type": "chunk", "index": data["index"], "text": text, "attacked": attacked,
                                    "status": "verified" if ok and state["failed"] is None else "rejected",
                                    "reason": reason, "signature_valid": r["signature_valid"], "aead_ok": r["aead_ok"]})
                    else:  # hash_chain
                        sig = _b64d(data["signature"]) if data.get("signature") else None
                        r = verify_hash_chain_chunk({"index": data["index"], "nonce": nonce, "ciphertext": ct,
                                                     "chain_hash": _b64d(data["chain_hash"]), "signature": sig},
                                                    chain_state, est.session_key, sig_public_key, client_crypto)
                        metrics["total_verify_ms"] += r["verify_ms"]
                        reason = None
                        if not r["aead_ok"]:
                            reason = "AEAD tag failed"
                        elif r["checkpoint_missing"]:
                            reason = "expected checkpoint missing"
                        elif r["checkpoint"] and not r["checkpoint_valid"]:
                            reason = "checkpoint signature does not match the chain"
                        if reason:
                            fail(reason, data["index"])
                        text = r["plaintext"].decode(errors="replace") if r["plaintext"] else None
                        state["pending"] += 1
                        metrics["max_unverified_chunks"] = max(metrics["max_unverified_chunks"], state["pending"])
                        out.append({"type": "chunk", "index": data["index"], "text": text, "attacked": attacked,
                                    "status": "rejected" if state["failed"] else "pending", "reason": reason,
                                    "signature_valid": r["checkpoint_valid"], "aead_ok": r["aead_ok"]})
                        if r["checkpoint"] and r["checkpoint_valid"] and state["failed"] is None:
                            state["pending"] = 0
                            out.append({"type": "covered", "upto": data["index"]})
                elif kind in ("final_buffered", "final_per_chunk", "final_chain"):
                    account(data)
                    state["terminal"] = True
                    text = None
                    if kind == "final_buffered":
                        r = verify_buffer_and_sign_final(
                            {"nonce": _b64d(data["nonce"]), "ciphertext": _b64d(data["ciphertext"]),
                             "signature": _b64d(data["signature"])},
                            est.session_key, sig_public_key, client_crypto, handshake_id)
                        ok = r["signature_valid"] and bool(r["aead_ok"])
                        text = r["plaintext"].decode(errors="replace") if r["plaintext"] else None
                        reason = None if ok else ("AEAD tag failed" if r["aead_ok"] is False else "signature invalid")
                    elif kind == "final_per_chunk":
                        r = verify_per_chunk_final({"n_chunks": data["n_chunks"], "signature": _b64d(data["signature"])},
                                                   state["expected"], sig_public_key, client_crypto, handshake_id)
                        ok = r["stream_fully_verified"]
                        reason = None if ok else ("end record signature invalid" if not r["signature_valid"]
                                                  else "chunk count does not match the signed end record")
                    else:
                        r = verify_hash_chain_final({"final_chain_hash": _b64d(data["final_chain_hash"]),
                                                     "n_chunks": data["n_chunks"], "signature": _b64d(data["signature"])},
                                                    chain_state, sig_public_key, client_crypto)
                        ok = r["stream_fully_verified"]
                        reason = None if ok else ("terminal signature invalid" if not r["signature_valid"]
                                                  else "chain or length does not match the signed terminal record")
                    metrics["total_verify_ms"] += r["verify_ms"]
                    if not ok:
                        fail(reason, "end")
                    verified = state["failed"] is None
                    metrics["stream_fully_verified"] = verified
                    if verified:
                        out.append({"type": "covered", "upto": metrics["n_chunks"] - 1})
                    out.append({"type": "final", "stream_fully_verified": verified, "reason": state["failed"],
                                "text": text})
                return out

            async with client.stream("POST", f"{base_url}/secure/predict/stream", json=payload) as resp:
                if resp.status_code != 200:
                    body = await resp.aread()
                    yield {"type": "error", "message": f"HTTP {resp.status_code}: {body[:200]}"}
                    return
                async for line in resp.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    data = json.loads(line[len("data:"):].strip())
                    if "kind" not in data:
                        continue  # the trailing "done" record is not signed data
                    if metrics["ttft_ms"] is None:
                        metrics["ttft_ms"] = (time.perf_counter() - t_start) * 1000
                    is_target = data.get("kind") == "chunk" and data.get("index") == attack_index
                    is_final = data.get("kind", "").startswith("final")
                    batch: list[tuple[dict, bool]] = [(data, False)]
                    if attack == "tamper_ciphertext" and (is_target or (strategy == "buffer_and_sign" and is_final)):
                        batch = [(_flip("ciphertext", data), True)]
                    elif attack == "tamper_signature" and data.get("signature") and (
                            is_target or (strategy != "per_chunk" and is_final)):
                        batch = [(_flip("signature", data), True)]
                    elif attack == "drop" and is_target:
                        batch = []
                    elif attack == "duplicate" and is_target:
                        batch = [(data, False), (dict(data), True)]
                    elif attack == "reorder" and is_target:
                        state["held"] = data
                        batch = []
                    elif attack == "reorder" and state["held"] is not None and data.get("kind") == "chunk":
                        batch = [(data, True), (state["held"], True)]
                        state["held"] = None
                    elif (attack == "strip_checkpoints" and strategy == "hash_chain" and data.get("kind") == "chunk"
                          and data.get("signature")):
                        batch = [({**data, "signature": None, "signature_bytes": 0}, True)]
                    if attack == "truncate" and strategy == "buffer_and_sign" and is_final:
                        break  # cut before the single signed envelope arrives
                    for rec, attacked in batch:
                        for ev in process(rec, attacked):
                            yield ev
                    if attack == "truncate" and is_target:
                        break  # the connection is cut: no further chunks, no terminal record

            metrics["total_ms"] = (time.perf_counter() - t_start) * 1000
            if not state["terminal"]:
                metrics["stream_fully_verified"] = False
                if state["failed"] is None:
                    state["failed"] = "stream ended without its signed terminal record (truncated)"
                yield {"type": "final", "stream_fully_verified": False, "reason": state["failed"], "text": None}
        yield {"type": "summary", "metrics": metrics}

    except Exception as exc:
        yield {"type": "error", "message": f"{type(exc).__name__}: {exc}"}
