"""Async load generator for a single (config, concurrency) cell.

Launches `--concurrency` concurrent workers, each repeatedly performing a
full protected transaction (handshake + predict + verify, via
api.secure_client.secure_predict_transaction) against an already-running
server, until `--requests` total transactions have completed. Samples the
server process's CPU% and RSS throughout via crypto.instrumentation.ResourceSampler.

For the unprotected "control" configuration, performs plain POST /predict
calls instead (no handshake, no crypto).

Writes one CSV row per request. Columns are a superset across configs; rows
for "control" leave the crypto-specific columns empty.

Usage:
    python -m bench.runner \
        --configuration full-pqc \
        --concurrency 10 \
        --requests 100 \
        --repetition 1 \
        --server-pid 12345 \
        --output results/raw/full-pqc-c10-r1.csv
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import time

import httpx

from api.secure_client import secure_predict_transaction
from crypto.instrumentation import ResourceSampler
from model.profiles.registry import get_profile

CONFIG_TO_MODULE_NAME = {
    "control": "control",
    "classical": "classical",
    "hybrid": "hybrid",
    "full-pqc": "full_pqc",
}

CSV_FIELDS = [
    "run_id", "config", "payload_profile", "concurrency", "repetition", "request_index",
    "rtt_ms", "handshake_ms", "total_ms",
    "client_establish_ms", "verify_ms", "valid_signature",
    "kex_blob_bytes", "signature_bytes",
    "request_plaintext_bytes", "response_plaintext_bytes", "response_ciphertext_bytes",
    "server_decapsulate_ms", "server_inference_ms", "server_encrypt_ms",
    "server_sign_ms", "server_crypto_ms", "server_total_ms",
    "prediction", "error",
]


def new_run_id() -> str:
    """One run_id per sweep invocation (shared across every cell/config in
    that sweep) so results/raw/ -- which accumulates every sweep ever run,
    forever, with no other separation between them -- can be filtered back
    down to "just this run" instead of silently blending in every prior
    run's data. Sortable lexicographically (== chronologically)."""
    import time

    return time.strftime("%Y%m%dT%H%M%S")


def _sample_request() -> dict:
    """Generates one request body matching whichever payload profile the
    PQ_SHIELD_PAYLOAD_PROFILE env var selects (default: tabular_small).
    Called fresh per request so profiles with multiple sample texts/images
    vary across a sweep rather than sending byte-identical requests."""
    return get_profile().sample_request()


async def _control_transaction(client: httpx.AsyncClient, base_url: str) -> dict:
    row = {"config": "control", "error": None}
    body = _sample_request()
    request_bytes = len(json.dumps(body).encode())
    t0 = time.perf_counter()
    try:
        resp = await client.post(f"{base_url}/predict", json=body)
        rtt_ms = (time.perf_counter() - t0) * 1000
        row["rtt_ms"] = rtt_ms
        row["total_ms"] = rtt_ms
        row["handshake_ms"] = 0.0
        row["request_plaintext_bytes"] = request_bytes
        if resp.status_code == 200:
            row["response_plaintext_bytes"] = len(resp.content)
            row["prediction"] = resp.json().get("prediction")
        else:
            row["error"] = f"HTTP {resp.status_code}"
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    return row


def _flatten(row: dict, config_name: str, concurrency: int, repetition: int, idx: int, run_id: str) -> dict:
    server_timing = row.get("server_timing_ms", {}) or {}
    debug = row.get("debug") or {}
    return {
        "run_id": run_id,
        "config": config_name,
        "payload_profile": get_profile().name,
        "concurrency": concurrency,
        "repetition": repetition,
        "request_index": idx,
        "rtt_ms": row.get("rtt_ms"),
        "handshake_ms": row.get("handshake_ms"),
        "total_ms": row.get("total_ms"),
        "client_establish_ms": row.get("client_establish_ms"),
        "verify_ms": row.get("verify_ms"),
        "valid_signature": row.get("valid_signature"),
        "kex_blob_bytes": row.get("kex_blob_bytes"),
        "signature_bytes": row.get("signature_bytes"),
        "request_plaintext_bytes": row.get("request_plaintext_bytes"),
        "response_plaintext_bytes": row.get("response_plaintext_bytes"),
        "response_ciphertext_bytes": debug.get("response_ciphertext_bytes"),
        "server_decapsulate_ms": server_timing.get("decapsulate_ms"),
        "server_inference_ms": server_timing.get("inference_ms"),
        "server_encrypt_ms": server_timing.get("encrypt_ms"),
        "server_sign_ms": server_timing.get("sign_ms"),
        "server_crypto_ms": server_timing.get("server_crypto_ms"),
        "server_total_ms": server_timing.get("server_total_ms"),
        "prediction": row.get("prediction"),
        "error": row.get("error"),
    }


async def run_sweep_cell(
    base_url: str,
    config_name: str,
    concurrency: int,
    n_requests: int,
    repetition: int,
    reuse_handshake: bool = False,
    run_id: str | None = None,
) -> list[dict]:
    """Runs one (config, concurrency, repetition) cell and returns flattened rows.

    `run_id` should be shared across every cell/config of one sweep (the
    caller generates it once via `new_run_id()` and passes it into every
    call) so the whole sweep is filterable as a single unit later. Defaults
    to a fresh id here only for standalone single-cell invocations."""
    run_id = run_id or new_run_id()
    results: list[dict] = []
    semaphore = asyncio.Semaphore(concurrency)
    counter = {"n": 0}
    counter_lock = asyncio.Lock()

    limits = httpx.Limits(max_connections=concurrency + 10, max_keepalive_connections=concurrency)
    async with httpx.AsyncClient(timeout=30.0, limits=limits) as client:
        cached_handshake = None
        if reuse_handshake and config_name != "control":
            from api.secure_client import do_handshake

            cached_handshake, _ = await do_handshake(client, base_url)

        async def worker():
            while True:
                async with counter_lock:
                    if counter["n"] >= n_requests:
                        return
                    idx = counter["n"]
                    counter["n"] += 1
                async with semaphore:
                    if config_name == "control":
                        row = await _control_transaction(client, base_url)
                    else:
                        row = await secure_predict_transaction(
                            client, base_url, config_name, _sample_request(),
                            debug_metrics=True, cached_handshake=cached_handshake,
                        )
                    results.append(_flatten(row, config_name, concurrency, repetition, idx, run_id))

        workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
        await asyncio.gather(*workers)

    return results


def write_csv(rows: list[dict], output_path: str) -> None:
    import os

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description="PQ-Shield single-cell benchmark runner")
    parser.add_argument("--configuration", required=True, choices=list(CONFIG_TO_MODULE_NAME.keys()))
    parser.add_argument("--concurrency", type=int, required=True)
    parser.add_argument("--requests", type=int, required=True, help="Total requests for this cell")
    parser.add_argument("--repetition", type=int, default=1)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--server-pid", type=int, default=None, help="PID to sample CPU/RSS from")
    parser.add_argument("--reuse-handshake", action="store_true")
    parser.add_argument("--warmup-fraction", type=float, default=0.05)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    config_name = CONFIG_TO_MODULE_NAME[args.configuration]

    sampler = None
    if args.server_pid:
        sampler = ResourceSampler(pid=args.server_pid, interval_s=0.25)
        sampler.start()

    t0 = time.perf_counter()
    rows = asyncio.run(
        run_sweep_cell(
            args.url, config_name, args.concurrency, args.requests, args.repetition,
            reuse_handshake=args.reuse_handshake,
        )
    )
    wall_s = time.perf_counter() - t0

    resource_summary = {}
    if sampler is not None:
        sampler.stop()
        resource_summary = sampler.summary()

    rows.sort(key=lambda r: r["request_index"])
    n_warmup = max(1, int(len(rows) * args.warmup_fraction)) if len(rows) > 20 else 0
    n_errors = sum(1 for r in rows if r["error"])

    write_csv(rows, args.output)

    summary = {
        "configuration": args.configuration,
        "concurrency": args.concurrency,
        "requests": args.requests,
        "repetition": args.repetition,
        "wall_seconds": wall_s,
        "throughput_rps": len(rows) / wall_s if wall_s > 0 else None,
        "n_errors": n_errors,
        "n_warmup_discarded_downstream": n_warmup,
        "output": args.output,
        "resource_summary": resource_summary,
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
