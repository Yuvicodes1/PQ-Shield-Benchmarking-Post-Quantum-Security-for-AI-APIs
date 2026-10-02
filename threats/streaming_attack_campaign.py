"""Large-sample stream-integrity campaign: static and adaptive sequence
attacks, with detection-rate confidence intervals and a false-rejection
baseline.

Collecting a fresh Llama response for every trial would make n >= 300 per
cell infeasible, and is unnecessary: whether the client detects an attack is
a deterministic function of the captured stream and where the attack lands.
So, per (configuration, strategy, checkpoint interval) cell, this script

  1. captures a pool of real protected streams from a real server
     (threats/streaming_mitm_experiment._collect_stream),
  2. verifies every pool stream unmodified -- the false-rejection baseline,
  3. runs `--trials` trials per attack, each on a random pool stream at a
     random position (and, for replay, with a different pool stream as the
     donor session), through the client's incremental verification
     (replay_through_client, the same checks api/secure_streaming_client.py
     makes).

Detection rates carry exact (Clopper-Pearson) 95% intervals. The trials
sample streams and attack positions; they are not independent network
events, which the paper states.

Attacks
  static    drop, reorder, duplicate, replay (one chunk from another session),
            truncate (cut at a random point; terminal record lost),
            session_replay (another session's whole stream and terminal record)
  adaptive  (hash chain with checkpoints)
            checkpoint_strip   remove every checkpoint signature
            checkpoint_move    move one checkpoint signature to the next chunk
            drop_before_ckpt   drop the chunk just before a checkpoint
            drop_after_ckpt    drop the chunk just after a checkpoint
            reorder_across     swap a checkpoint chunk with the chunk after it
  checkpoint_strip also runs against the v2 client, which did not enforce the
  requested checkpoint schedule ("checkpoint_strip_v2client").

    python -m threats.streaming_attack_campaign --trials 500 --pool 10
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import time

import httpx

from bench.orchestrator import REPO_ROOT, _start_server, _stop_server, _wait_healthy
from threats.key_substitution import clopper_pearson
from threats.streaming_mitm_experiment import CONFIG_TO_CRYPTO_NAME, DEFAULT_PROMPT, _collect_stream, replay_through_client

STATIC = ["drop", "reorder", "duplicate", "replay", "truncate", "session_replay"]
ADAPTIVE = ["checkpoint_strip", "checkpoint_strip_v2client", "checkpoint_move",
            "drop_before_ckpt", "drop_after_ckpt", "reorder_across"]
# (strategy, checkpoint interval) cells per configuration
CELLS = [("per_chunk", None), ("hash_chain", None), ("hash_chain", 2), ("hash_chain", 5), ("hash_chain", 10)]


def _ckpt_positions(chunks: list[dict]) -> list[int]:
    return [i for i, c in enumerate(chunks) if c.get("signature")]


def _mutate(rng: random.Random, cap: dict, donor: dict, attack: str, strategy: str):
    """Returns (victim_capture, mutated_chunks, final, first_affected_position)
    or None if the attack does not apply to this stream. first_affected is
    the first position whose content differs from the genuine stream: a
    client displaying chunks as they arrive has shown `first_affected`
    genuine chunks, and everything from there to the detection point is
    attacker-influenced exposure."""
    chunks, final = list(cap["chunks"]), cap["final"]
    n = len(chunks)
    if attack == "drop":
        i = rng.randrange(0, n)
        return cap, chunks[:i] + chunks[i + 1:], final, i
    if attack == "reorder":
        i = rng.randrange(0, n - 1)
        chunks[i], chunks[i + 1] = chunks[i + 1], chunks[i]
        return cap, chunks, final, i
    if attack == "duplicate":
        i = rng.randrange(0, n)
        return cap, chunks[:i + 1] + [dict(chunks[i])] + chunks[i + 1:], final, i + 1
    if attack == "replay":
        i = rng.randrange(0, min(n, len(donor["chunks"])))
        chunks[i] = dict(donor["chunks"][i])
        return cap, chunks, final, i
    if attack == "truncate":
        cut = rng.randrange(1, n + 1)  # n = all chunks delivered, only the terminal record lost
        return cap, chunks[:cut], None, cut
    if attack == "session_replay":
        return cap, list(donor["chunks"]), donor["final"], 0

    ck = _ckpt_positions(chunks)
    if strategy != "hash_chain" or not ck:
        return None
    if attack in ("checkpoint_strip", "checkpoint_strip_v2client"):
        stripped = [dict(c, signature=None, signature_bytes=0) if c.get("signature") else c for c in chunks]
        return cap, stripped, final, ck[0]
    j = rng.choice(ck)
    if attack == "checkpoint_move":
        if j + 1 >= n:
            return None
        chunks[j + 1] = dict(chunks[j + 1], signature=chunks[j]["signature"])
        chunks[j] = dict(chunks[j], signature=None)
        return cap, chunks, final, j
    if attack == "drop_before_ckpt":
        if j == 0:
            return None
        return cap, chunks[:j - 1] + chunks[j:], final, j - 1
    if attack == "drop_after_ckpt":
        if j + 1 >= n:
            return None
        return cap, chunks[:j + 1] + chunks[j + 2:], final, j + 1
    if attack == "reorder_across":
        if j + 1 >= n:
            return None
        chunks[j], chunks[j + 1] = chunks[j + 1], chunks[j]
        return cap, chunks, final, j
    raise ValueError(attack)


def run_cell(pool: list[dict], cfg: str, strategy: str, k: int | None, trials: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    out = []
    # False-rejection baseline: every genuine stream must verify.
    false_rej = sum(replay_through_client(c, c["chunks"], c["final"], strategy, k) is not None for c in pool)
    out.append({"config": cfg, "strategy": strategy, "checkpoint_interval": k, "attack": "benign",
                "n": len(pool), "detected": false_rej, "detected_ci95": clopper_pearson(false_rej, len(pool)),
                "mid_stream": None, "exposure_chunks_mean": None, "exposure_chunks_max": None,
                "unverified_at_detection_mean": None, "unverified_at_detection_max": None,
                "n_chunks_mean": sum(len(c["chunks"]) for c in pool) / len(pool)})
    attacks = STATIC + (ADAPTIVE if strategy == "hash_chain" and k else [])
    for attack in attacks:
        n = det = mid = 0
        exposures, unverified = [], []
        tries = 0
        while n < trials and tries < trials * 5:
            tries += 1
            a, b = rng.sample(range(len(pool)), 2)
            m = _mutate(rng, pool[a], pool[b], attack, strategy)
            if m is None:
                continue
            cap, mutated, final, first = m
            pos, covered = replay_through_client(cap, mutated, final, strategy, k, details=True,
                                                 enforce_schedule=attack != "checkpoint_strip_v2client")
            n += 1
            if pos is not None:
                det += 1
                mid += pos < len(mutated)
                # attacker-influenced chunks a streaming UI displayed before rejection
                exposures.append(max(0, pos - first))
                # chunks displayed with no verified signature covering them when rejected
                unverified.append(pos - covered)
            elif attack == "checkpoint_strip_v2client":
                # accepted -- the cost is that nothing was covered until the end
                unverified.append(len(mutated))
        out.append({"config": cfg, "strategy": strategy, "checkpoint_interval": k, "attack": attack,
                    "n": n, "detected": det, "detected_ci95": clopper_pearson(det, n) if n else None,
                    "mid_stream": mid,
                    "exposure_chunks_mean": sum(exposures) / len(exposures) if exposures else None,
                    "exposure_chunks_max": max(exposures) if exposures else None,
                    "unverified_at_detection_mean": sum(unverified) / len(unverified) if unverified else None,
                    "unverified_at_detection_max": max(unverified) if unverified else None,
                    "n_chunks_mean": sum(len(c["chunks"]) for c in pool) / len(pool)})
    return out


async def _collect_pool(base_url: str, crypto: str, strategy: str, k: int | None, size: int,
                        max_tokens: int, chunk_size_tokens: int) -> list[dict]:
    pool = []
    async with httpx.AsyncClient(timeout=120.0) as client:
        for _ in range(size):
            pool.append(await _collect_stream(client, base_url, crypto, strategy, DEFAULT_PROMPT,
                                              max_tokens, chunk_size_tokens, k))
    return pool


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--configs", default="classical,classical-ecdhe,hybrid,hybrid-kex,full-pqc,hybrid-kex-pq")
    ap.add_argument("--trials", type=int, default=500)
    ap.add_argument("--pool", type=int, default=10)
    ap.add_argument("--max-tokens", type=int, default=100)
    ap.add_argument("--chunk-size-tokens", type=int, default=5)
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--seed", type=int, default=20261003)
    ap.add_argument("--output", default=os.path.join(REPO_ROOT, "results", "streaming", "mitm", "campaign.json"))
    ap.add_argument("--log-dir", default=os.path.join(REPO_ROOT, "results", "server_logs"))
    args = ap.parse_args()
    base_url = f"http://127.0.0.1:{args.port}"
    rows: list[dict] = []
    for ci, key in enumerate([c.strip() for c in args.configs.split(",") if c.strip()]):
        crypto = CONFIG_TO_CRYPTO_NAME[key]
        proc = _start_server(key, args.port, os.path.join(args.log_dir, f"campaign-server-{key}.log"))
        try:
            _wait_healthy(base_url, timeout_s=120.0)
            for si, (strategy, k) in enumerate(CELLS):
                t0 = time.perf_counter()
                pool = asyncio.run(_collect_pool(base_url, crypto, strategy, k, args.pool,
                                                 args.max_tokens, args.chunk_size_tokens))
                cell = run_cell(pool, crypto, strategy, k, args.trials, args.seed + 100 * ci + si)
                rows += cell
                print(f"[{key} {strategy} k={k}] pool {len(pool)} in {time.perf_counter() - t0:.0f}s", flush=True)
                for r in cell:
                    print(f"    {r['attack']:<26} {r['detected']:>4}/{r['n']:<4} mid={r['mid_stream']} "
                          f"exposure_mean={r['exposure_chunks_mean']} unverified_mean={r['unverified_at_detection_mean']}", flush=True)
        finally:
            _stop_server(proc)
            time.sleep(1.0)
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        with open(args.output, "w") as f:  # rewritten per config so a partial run is usable
            json.dump({"backend": os.environ.get("PQ_SHIELD_STREAMING_BACKEND", "synthetic"),
                       "trials": args.trials, "pool": args.pool, "max_tokens": args.max_tokens,
                       "seed": args.seed, "rows": rows}, f, indent=2)
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
