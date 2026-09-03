"""Shared CLI entrypoint used by client.py / client_hybrid.py / client_full_pqc.py.

Each of those files just calls `main("classical" | "hybrid" | "full_pqc")`.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os

import httpx

from api.secure_client import secure_predict_transaction
from model.profiles.registry import PROFILE_NAMES


def _parse_args():
    parser = argparse.ArgumentParser(description="PQ-Shield protected client")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Base URL of the secure server")
    parser.add_argument(
        "--profile", default=None, choices=PROFILE_NAMES,
        help="Payload profile to sample a request from (default: server's configured profile, "
             "PQ_SHIELD_PAYLOAD_PROFILE env var, normally tabular_small). Must match what the "
             "server is actually running, or /secure/predict will reject the request.",
    )
    parser.add_argument(
        "--features",
        default=None,
        help="Comma-separated 64 pixel values (0-16) -- only meaningful with the tabular_small "
             "profile; overrides --profile's random sample for that profile specifically.",
    )
    parser.add_argument("--debug-metrics", action="store_true", help="Request byte-size debug metadata")
    return parser.parse_args()


def main(config_name: str) -> None:
    args = _parse_args()
    if args.profile:
        os.environ["PQ_SHIELD_PAYLOAD_PROFILE"] = args.profile

    # Imported after the env var is set, since get_profile() reads it fresh
    # on first call -- but deferred import here also just keeps the module
    # import graph flat for this simple CLI entrypoint.
    from model.profiles.registry import get_profile

    if args.features is not None:
        request_body = {"input": [float(v) for v in args.features.split(",")]}
    else:
        request_body = get_profile().sample_request()

    async def _run():
        async with httpx.AsyncClient(timeout=30.0) as client:
            row = await secure_predict_transaction(
                client, args.url, config_name, request_body, debug_metrics=args.debug_metrics
            )
            print(json.dumps(row, indent=2, default=str))

    asyncio.run(_run())
