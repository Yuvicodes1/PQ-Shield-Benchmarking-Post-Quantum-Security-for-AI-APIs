"""Streaming-specific active MITM threat: an attacker who silently drops or
reorders one chunk mid-stream.

WHY THIS IS A DIFFERENT EXPERIMENT FROM threats/mitm_experiment.py
--------------------------------------------------------------------
The existing MITM experiment corrupts a byte in the ciphertext or signature
of a single, complete response. For streaming, that same byte-corruption
attack is caught *immediately* by AES-GCM authentication the instant the
tampered chunk arrives -- true in all three signing strategies
(crypto/streaming.py), so it does not differentiate them and re-running it
chunk-by-chunk would not teach anything new.

What *does* differ by strategy is a **sequence-integrity** attack: silently
dropping a chunk, or swapping two chunks' order, without touching any single
chunk's bytes. per_chunk signs `index || nonce || ciphertext`, so a client
tracking the expected index flags this on the very next chunk it receives.
hash_chain deliberately defers its sequence guarantee to the *terminating*
signature (see crypto/streaming.py's module docstring) to amortize signing
cost across the whole stream -- so a drop/reorder attack is invisible to the
client until the stream has already finished arriving. This script measures
exactly that gap: what fraction of the response the client would already
have consumed (and, in a real chat UI, likely already rendered) before the
tamper is caught, per strategy. buffer_and_sign never delivers anything
before the end regardless, so it has no such exposure window by
construction -- included in the results as a qualitative "not applicable",
not a fabricated number.

Usage:
    python -m threats.streaming_mitm_experiment \
        --configs classical,hybrid,full-pqc \
        --strategies per_chunk,hash_chain \
        --attacks drop,reorder \
        --trials 20
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time

import httpx

from api.secure_client import _b64d, _b64e, do_handshake
from bench.orchestrator import REPO_ROOT, SERVER_MODULES, _start_server, _stop_server, _wait_healthy
from crypto.aead import aead_encrypt
from crypto.registry import get_client_crypto
from crypto.streaming import HashChainClientState, verify_hash_chain_chunk, verify_hash_chain_final, verify_per_chunk

DEFAULT_PROMPT = (
    "Summarize the key risks of migrating a production API to post-quantum "
    "cryptography, focusing on latency-sensitive workloads."
)

CONFIG_TO_CRYPTO_NAME = {"classical": "classical", "hybrid": "hybrid", "full-pqc": "full_pqc"}
ATTACKABLE_STRATEGIES = ["per_chunk", "hash_chain"]  # buffer_and_sign has no intermediate chunks


async def run_trial(
    client: httpx.AsyncClient,
    base_url: str,
    config_name: str,
    strategy: str,
    attack: str,
    prompt: str = DEFAULT_PROMPT,
    max_tokens: int = 60,
    chunk_size_tokens: int = 5,
) -> dict:
    """One trial: collect a real streaming response in full, apply `attack`
    ("drop" or "reorder") to the middle of its chunk sequence -- exactly what
    an active proxy sitting on the wire could do to the SSE bytes without
    forging any single chunk's contents -- then replay the mutated sequence
    through the same client-side verification logic
    (crypto/streaming.py's verify_per_chunk / verify_hash_chain_chunk) a real
    client runs incrementally, tracking the position (if any) where the
    tamper is first flagged.
    """
    client_crypto = get_client_crypto(config_name)
    result: dict = {
        "config": config_name, "strategy": strategy, "attack": attack, "error": None,
        "n_chunks": None, "detected": None, "detected_mid_stream": None,
        "chunks_before_detection": None, "fraction_delivered_before_detection": None,
    }

    if strategy not in ATTACKABLE_STRATEGIES:
        result["error"] = (
            "not applicable -- buffer_and_sign has no intermediate chunks to attack; "
            "it never delivers anything before the end regardless"
        )
        return result

    try:
        handshake_json, _ = await do_handshake(client, base_url)
        kex_public_key = _b64d(handshake_json["kex_public_key"])
        sig_public_key = _b64d(handshake_json["sig_public_key"])
        handshake_id = handshake_json["handshake_id"]
        est = client_crypto.establish(kex_public_key)

        request_body = {
            "prompt": prompt, "strategy": strategy,
            "chunk_size_tokens": chunk_size_tokens, "max_tokens": max_tokens,
        }
        request_plaintext = json.dumps(request_body).encode()
        req_aead = aead_encrypt(est.session_key, request_plaintext)
        payload = {
            "handshake_id": handshake_id, "kex_blob": _b64e(est.kex_blob),
            "nonce": _b64e(req_aead.nonce), "ciphertext": _b64e(req_aead.ciphertext),
        }

        chunks: list[dict] = []
        final_event: dict | None = None
        async with client.stream("POST", f"{base_url}/secure/predict/stream", json=payload, timeout=60.0) as resp:
            if resp.status_code != 200:
                result["error"] = f"HTTP {resp.status_code}"
                return result
            async for line in resp.aiter_lines():
                if not line.startswith("data:"):
                    continue
                data = json.loads(line[len("data:"):].strip())
                kind = data.get("kind")
                if kind == "chunk":
                    chunks.append(data)
                elif kind in ("final_buffered", "final_chain"):
                    final_event = data
                # else: the trailing "event: done" trailer's data line (no "kind" field
                # at all) -- not a signed/verifiable event, must not be mistaken for one.

        result["n_chunks"] = len(chunks)
        if len(chunks) < 3:
            result["error"] = f"stream too short to attack ({len(chunks)} chunks, need >=3)"
            return result

        # --- the attacker acts here: mutate the sequence, touching no chunk's own bytes ---
        mutated = list(chunks)
        mid = len(mutated) // 2
        if attack == "drop":
            del mutated[mid]
        elif attack == "reorder":
            mutated[mid], mutated[mid + 1] = mutated[mid + 1], mutated[mid]
        else:
            raise ValueError(f"Unknown attack {attack!r}. Valid: drop, reorder")

        detected_at = None  # 0-based position in `mutated` where first flagged, if any

        if strategy == "per_chunk":
            expected_index = 0
            for pos, data in enumerate(mutated):
                chunk = {
                    "index": data["index"], "nonce": _b64d(data["nonce"]),
                    "ciphertext": _b64d(data["ciphertext"]), "signature": _b64d(data["signature"]),
                }
                r = verify_per_chunk(chunk, expected_index, est.session_key, sig_public_key, client_crypto)
                expected_index += 1
                if detected_at is None and (not r["in_order"] or not r["signature_valid"] or not bool(r["aead_ok"])):
                    detected_at = pos
            result["detected_mid_stream"] = detected_at is not None
            result["detected"] = detected_at is not None

        elif strategy == "hash_chain":
            chain_state = HashChainClientState()
            for pos, data in enumerate(mutated):
                chunk = {
                    "index": data["index"], "nonce": _b64d(data["nonce"]),
                    "ciphertext": _b64d(data["ciphertext"]), "chain_hash": _b64d(data["chain_hash"]),
                }
                r = verify_hash_chain_chunk(chunk, chain_state, est.session_key)
                if detected_at is None and not bool(r["aead_ok"]):
                    detected_at = pos  # would only fire for byte-level tampering, not drop/reorder
            mid_stream_detected = detected_at is not None
            final_detected = False
            if final_event is not None and final_event.get("kind") == "final_chain":
                final_chunk = {
                    "final_chain_hash": _b64d(final_event["final_chain_hash"]),
                    "signature": _b64d(final_event["signature"]),
                }
                fr = verify_hash_chain_final(final_chunk, chain_state, sig_public_key, client_crypto)
                final_detected = not fr["stream_fully_verified"]
            result["detected_mid_stream"] = mid_stream_detected
            result["detected"] = mid_stream_detected or final_detected

        result["chunks_before_detection"] = detected_at if detected_at is not None else len(mutated)
        result["fraction_delivered_before_detection"] = result["chunks_before_detection"] / len(mutated)

    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    return result


def summarize(rows: list[dict], config: str, strategy: str, attack: str) -> dict:
    """One summary dict for one (config, strategy, attack) combination,
    matching the shape/spirit of threats/mitm_experiment.py's per-combo
    summaries -- detection_rate as the headline number -- plus the
    streaming-specific fraction_delivered_before_detection_mean, which is
    what actually differs between per_chunk and hash_chain here."""
    valid = [r for r in rows if r.get("error") is None]
    n = len(rows)
    n_valid = len(valid)
    n_detected = sum(1 for r in valid if r.get("detected"))
    n_detected_mid_stream = sum(1 for r in valid if r.get("detected_mid_stream"))
    fractions = [r["fraction_delivered_before_detection"] for r in valid
                 if r.get("fraction_delivered_before_detection") is not None]
    return {
        "config": config, "strategy": strategy, "attack": attack,
        "n_trials": n, "n_valid_trials": n_valid,
        "detection_rate": (n_detected / n_valid) if n_valid else None,
        "mid_stream_detection_rate": (n_detected_mid_stream / n_valid) if n_valid else None,
        "fraction_delivered_before_detection_mean": (sum(fractions) / len(fractions)) if fractions else None,
    }


async def run_experiment(
    configs: list[str], strategies: list[str], attacks: list[str], trials: int,
    base_url: str, prompt: str = DEFAULT_PROMPT, max_tokens: int = 60, chunk_size_tokens: int = 5,
) -> tuple[list[dict], list[dict]]:
    """Runs `trials` repetitions of every (config, strategy, attack) combo
    against an already-running server for that config. Returns
    (raw_rows, summaries) -- the dashboard's live-run button uses this
    directly (it manages the server itself via server_manager); the CLI
    below wraps it with its own start/stop/summary-file-writing per config."""
    raw_rows = []
    summaries = []
    async with httpx.AsyncClient(timeout=60.0) as client:
        for config_name in configs:
            for strategy in strategies:
                combo_attacks = attacks if strategy in ATTACKABLE_STRATEGIES else [attacks[0]]
                for attack in combo_attacks:
                    combo_rows = []
                    n_trials = trials if strategy in ATTACKABLE_STRATEGIES else 1
                    for _ in range(n_trials):
                        row = await run_trial(
                            client, base_url, config_name, strategy, attack,
                            prompt=prompt, max_tokens=max_tokens, chunk_size_tokens=chunk_size_tokens,
                        )
                        combo_rows.append(row)
                    raw_rows.extend(combo_rows)
                    summaries.append(summarize(combo_rows, config_name, strategy, attack))
    return raw_rows, summaries


def main():
    parser = argparse.ArgumentParser(description="PQ-Shield streaming sequence-integrity MITM experiment")
    parser.add_argument("--configs", default="classical,hybrid,full-pqc")
    parser.add_argument("--strategies", default="buffer_and_sign,per_chunk,hash_chain")
    parser.add_argument("--attacks", default="drop,reorder")
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--max-tokens", type=int, default=60)
    parser.add_argument("--chunk-size-tokens", type=int, default=5)
    parser.add_argument("--output-dir", default=os.path.join(REPO_ROOT, "results", "streaming", "mitm"))
    parser.add_argument("--log-dir", default=os.path.join(REPO_ROOT, "results", "server_logs"))
    args = parser.parse_args()

    configs = [c.strip() for c in args.configs.split(",") if c.strip()]
    strategies = [s.strip() for s in args.strategies.split(",") if s.strip()]
    attacks = [a.strip() for a in args.attacks.split(",") if a.strip()]
    os.makedirs(args.output_dir, exist_ok=True)
    os.makedirs(args.log_dir, exist_ok=True)
    base_url = f"http://127.0.0.1:{args.port}"

    for config_key in configs:
        crypto_name = CONFIG_TO_CRYPTO_NAME[config_key]
        log_path = os.path.join(args.log_dir, f"streaming-mitm-server-{config_key}.log")
        print(f"\n=== Starting server: {config_key} ({SERVER_MODULES[config_key]}) ===", flush=True)
        proc = _start_server(config_key, args.port, log_path)
        try:
            _wait_healthy(base_url)
            print(f"Server healthy (pid={proc.pid}).", flush=True)

            _, summaries = asyncio.run(run_experiment(
                [crypto_name], strategies, attacks, args.trials, base_url,
                max_tokens=args.max_tokens, chunk_size_tokens=args.chunk_size_tokens,
            ))
            for s in summaries:
                if s["detection_rate"] is None:
                    print(f"  {s['config']:<10} {s['strategy']:<16} {s['attack']:<8} -> n/a", flush=True)
                else:
                    print(
                        f"  {s['config']:<10} {s['strategy']:<16} {s['attack']:<8} -> "
                        f"detected={s['detection_rate']:.0%} mid_stream={s['mid_stream_detection_rate']:.0%} "
                        f"fraction_delivered_before_detection="
                        f"{s['fraction_delivered_before_detection_mean']:.2f}",
                        flush=True,
                    )
                out_path = os.path.join(args.output_dir, f"{crypto_name}-{s['strategy']}-{s['attack']}-summary.json")
                with open(out_path, "w") as f:
                    json.dump(s, f, indent=2)
        finally:
            print(f"Stopping server: {config_key}", flush=True)
            _stop_server(proc)
            time.sleep(1.0)


if __name__ == "__main__":
    main()
