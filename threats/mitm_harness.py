"""Threat Scenario 2 -- active Man-in-the-Middle (MITM) tamper detection.

Implements a minimal asyncio HTTP/1.1 forward proxy (no external MITM
dependency such as `mitmproxy` -- consistent with this project's "no
system-wide installation required" design goal) that sits between the
client and a running secure server. For POST /secure/predict responses
specifically, the proxy flips one byte inside the AES-GCM ciphertext body
before forwarding it to the client.

Because response confidentiality is AES-256-GCM (authenticated encryption),
tampering with the ciphertext is expected to be caught at the
*decryption* step (GCM tag mismatch) before signature verification is even
reached in the client's normal code path. To specifically exercise the
*signature* layer (which is what RQ4 / H4 is about), this harness also
supports a `--tamper-target signature` mode that flips a byte in the
signature field instead, leaving the ciphertext untouched -- this isolates
ML-DSA-65 vs. ECDSA tamper-detection latency from AES-GCM's own tamper
detection.

Usage:
    # 1. Start a secure server, e.g.:
    #      uvicorn api.server_config_c:app --port 8000
    # 2. Start the tampering proxy in front of it:
    python -m threats.mitm_harness --upstream http://127.0.0.1:8000 \
        --listen-port 8080 --tamper-target ciphertext
    # 3. Point a client at the proxy instead of the server directly:
    python -m api.client_full_pqc --url http://127.0.0.1:8080
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging

from aiohttp import web

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("mitm_harness")


def _tamper_response_body(body: bytes, tamper_target: str) -> bytes:
    """Flips one byte in either the base64 ciphertext or signature field of
    a /secure/predict JSON response. Returns the tampered body bytes."""
    try:
        payload = json.loads(body)
    except Exception:
        return body  # not JSON (e.g. an error response) -- pass through unmodified

    field = "ciphertext" if tamper_target == "ciphertext" else "signature"
    if field not in payload or not payload[field]:
        return body

    import base64

    raw = bytearray(base64.b64decode(payload[field]))
    if not raw:
        return body
    raw[len(raw) // 2] ^= 0xFF  # flip a bit in the middle of the field
    payload[field] = base64.b64encode(bytes(raw)).decode("ascii")
    payload["_mitm_tampered"] = tamper_target
    return json.dumps(payload).encode()


def build_proxy_app(upstream: str, tamper_target: str, tamper_probability: float) -> web.Application:
    import random

    import aiohttp

    async def handle(request: web.Request) -> web.Response:
        url = f"{upstream}{request.path_qs}"
        body = await request.read()
        async with aiohttp.ClientSession() as session:
            async with session.request(
                request.method, url, data=body, headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
            ) as upstream_resp:
                resp_body = await upstream_resp.read()
                should_tamper = (
                    request.path.endswith("/secure/predict")
                    and request.method == "POST"
                    and upstream_resp.status == 200
                    and random.random() < tamper_probability
                )
                if should_tamper:
                    original_len = len(resp_body)
                    resp_body = _tamper_response_body(resp_body, tamper_target)
                    logger.info(
                        "TAMPERED response on %s (target=%s, %d -> %d bytes)",
                        request.path, tamper_target, original_len, len(resp_body),
                    )
                return web.Response(
                    body=resp_body,
                    status=upstream_resp.status,
                    headers={
                        k: v
                        for k, v in upstream_resp.headers.items()
                        if k.lower() not in ("content-length", "content-encoding", "transfer-encoding")
                    },
                )

    app = web.Application()
    app.router.add_route("*", "/{path_info:.*}", handle)
    return app


def main():
    parser = argparse.ArgumentParser(description="PQ-Shield MITM tamper-injection proxy")
    parser.add_argument("--upstream", required=True, help="Base URL of the real secure server")
    parser.add_argument("--listen-port", type=int, default=8080)
    parser.add_argument(
        "--tamper-target", choices=["ciphertext", "signature"], default="ciphertext",
        help="Which field of the /secure/predict response to corrupt",
    )
    parser.add_argument(
        "--tamper-probability", type=float, default=1.0,
        help="Fraction of /secure/predict responses to tamper with (1.0 = always)",
    )
    args = parser.parse_args()

    app = build_proxy_app(args.upstream, args.tamper_target, args.tamper_probability)
    logger.info(
        "MITM proxy listening on :%d -> %s (tamper_target=%s, p=%.2f)",
        args.listen_port, args.upstream, args.tamper_target, args.tamper_probability,
    )
    web.run_app(app, port=args.listen_port, print=None)


if __name__ == "__main__":
    main()
