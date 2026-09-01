"""Benchmarks streaming signature overhead across configurations, strategies,
and response sizes -- the experiment that produces the actual numbers behind
the claims in docs/STREAMING.md (e.g. "N tokens per_chunk costs X KB of
signatures vs Y KB for hash_chain").

Unlike bench/orchestrator.py's concurrency sweep, this is deliberately a
low-concurrency, one-transaction-at-a-time sweep: the variable under study
here is response size and signing strategy, not concurrent load. Combining
both in one experiment would confound the two; see docs/STREAMING.md
"Relationship to the main benchmark" for why they are kept separate.

Usage:
    python -m bench.streaming_runner \
        --configs classical,hybrid,full-pqc \
        --strategies buffer_and_sign,per_chunk,hash_chain \
        --max-tokens 50,200,500 \
        --chunk-size-tokens 1,5,20 \
        --repetitions 3

Requires a running server for each configuration on the given port (the
script starts/stops them itself, one at a time, exactly like
bench/orchestrator.py's main sweep).
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import itertools
import os
import time

import httpx

from api.secure_streaming_client import run_streaming_transaction
from bench.orchestrator import REPO_ROOT, SERVER_MODULES, _start_server, _stop_server, _wait_healthy

DEFAULT_PROMPT = (
    "Summarize the key risks of migrating a production API to post-quantum "
    "cryptography, focusing on latency-sensitive workloads."
)

CONFIG_TO_CRYPTO_NAME = {"classical": "classical", "hybrid": "hybrid", "full-pqc": "full_pqc"}

CSV_FIELDS = [
    "config", "strategy", "max_tokens", "chunk_size_tokens", "repetition",
    "handshake_ms", "ttft_ms", "total_ms",
    "n_chunks", "total_signature_bytes", "total_signing_ms", "total_verify_ms",
    "all_signatures_valid", "all_aead_ok", "all_in_order", "stream_fully_verified",
    "reconstructed_bytes", "error",
]


async def _run_one(base_url: str, config_key: str, strategy: str, max_tokens: int,
                    chunk_size_tokens: int, repetition: int) -> dict:
    crypto_name = CONFIG_TO_CRYPTO_NAME[config_key]
    async with httpx.AsyncClient(timeout=60.0) as client:
        metrics = await run_streaming_transaction(
            client, base_url, crypto_name, DEFAULT_PROMPT, strategy,
            chunk_size_tokens=chunk_size_tokens, max_tokens=max_tokens,
        )
    metrics["max_tokens"] = max_tokens
    metrics["chunk_size_tokens"] = chunk_size_tokens
    metrics["repetition"] = repetition
    return {k: metrics.get(k) for k in CSV_FIELDS}


def run_sweep(configs: list[str], strategies: list[str], max_tokens_values: list[int],
              chunk_size_values: list[int], repetitions: int, port: int,
              output_dir: str, log_dir: str) -> list[dict]:
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)
    base_url = f"http://127.0.0.1:{port}"
    all_rows = []

    for config_key in configs:
        log_path = os.path.join(log_dir, f"streaming-server-{config_key}.log")
        print(f"\n=== Starting server: {config_key} ({SERVER_MODULES[config_key]}) ===", flush=True)
        proc = _start_server(config_key, port, log_path)
        try:
            _wait_healthy(base_url)
            print(f"Server healthy (pid={proc.pid}).", flush=True)

            rows = []
            combos = list(itertools.product(strategies, max_tokens_values, chunk_size_values))
            for strategy, max_tokens, chunk_size in combos:
                for rep in range(1, repetitions + 1):
                    row = asyncio.run(
                        _run_one(base_url, config_key, strategy, max_tokens, chunk_size, rep)
                    )
                    rows.append(row)
                    if row["error"]:
                        print(f"  {config_key:<10} {strategy:<16} tokens={max_tokens:<5} "
                              f"chunk={chunk_size:<4} rep={rep} -> ERROR: {row['error']}", flush=True)
                    else:
                        print(f"  {config_key:<10} {strategy:<16} tokens={max_tokens:<5} "
                              f"chunk={chunk_size:<4} rep={rep} -> "
                              f"ttft={row['ttft_ms']:.1f}ms sig_bytes={row['total_signature_bytes']:<7} OK",
                              flush=True)

            out_path = os.path.join(output_dir, f"{config_key}-streaming.csv")
            with open(out_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                writer.writeheader()
                writer.writerows(rows)
            print(f"Wrote {len(rows)} rows to {out_path}", flush=True)
            all_rows.extend(rows)
        finally:
            print(f"Stopping server: {config_key}", flush=True)
            _stop_server(proc)
            time.sleep(1.0)

    return all_rows


def main():
    parser = argparse.ArgumentParser(description="PQ-Shield streaming signature-overhead sweep")
    parser.add_argument("--configs", default="classical,hybrid,full-pqc")
    parser.add_argument("--strategies", default="buffer_and_sign,per_chunk,hash_chain")
    parser.add_argument("--max-tokens", default="50,200,500", help="Comma-separated response lengths")
    parser.add_argument("--chunk-size-tokens", default="1,5,20", help="Comma-separated chunk granularities")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--output-dir", default=os.path.join(REPO_ROOT, "results", "streaming"))
    parser.add_argument("--log-dir", default=os.path.join(REPO_ROOT, "results", "server_logs"))
    args = parser.parse_args()

    configs = [c.strip() for c in args.configs.split(",") if c.strip()]
    strategies = [s.strip() for s in args.strategies.split(",") if s.strip()]
    max_tokens_values = [int(x) for x in args.max_tokens.split(",") if x.strip()]
    chunk_size_values = [int(x) for x in args.chunk_size_tokens.split(",") if x.strip()]

    run_sweep(configs, strategies, max_tokens_values, chunk_size_values,
              args.repetitions, args.port, args.output_dir, args.log_dir)


if __name__ == "__main__":
    main()
