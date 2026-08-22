"""Shared CLI entrypoint used by client.py / client_hybrid.py / client_full_pqc.py.

Each of those files just calls `main("classical" | "hybrid" | "full_pqc")`.
"""

from __future__ import annotations

import argparse
import asyncio
import json

import httpx

from api.secure_client import secure_predict_transaction

DEFAULT_FEATURES = (
    "0,0,5,13,9,1,0,0,0,0,13,15,10,15,5,0,0,3,15,2,0,11,8,0,0,4,12,0,0,8,8,0,"
    "0,5,8,0,0,9,8,0,0,4,11,0,1,12,7,0,0,2,14,5,10,12,0,0,0,0,6,13,10,0,0,0"
)


def _parse_args():
    parser = argparse.ArgumentParser(description="PQ-Shield protected client")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Base URL of the secure server")
    parser.add_argument(
        "--features",
        default=DEFAULT_FEATURES,
        help="Comma-separated 64 pixel values (0-16)",
    )
    parser.add_argument("--debug-metrics", action="store_true", help="Request byte-size debug metadata")
    return parser.parse_args()


def main(config_name: str) -> None:
    args = _parse_args()
    features = [float(v) for v in args.features.split(",")]

    async def _run():
        async with httpx.AsyncClient(timeout=30.0) as client:
            row = await secure_predict_transaction(
                client, args.url, config_name, features, debug_metrics=args.debug_metrics
            )
            print(json.dumps(row, indent=2, default=str))

    asyncio.run(_run())
