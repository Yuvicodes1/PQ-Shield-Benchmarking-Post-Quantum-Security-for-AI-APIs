"""Async raw-metric runner for the control and Configuration A endpoints."""

import argparse
import asyncio
import json
import os
from pathlib import Path
import resource
from time import perf_counter

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

from bench.metrics import RequestMetric, write_metrics
from crypto.config_a_classical import b64, pack_envelope, unb64, unpack_envelope

DEFAULT_FEATURES = [0.0] * 64


async def control_request(client: httpx.AsyncClient) -> tuple[float, float, float]:
    started = perf_counter()
    response = await client.post("/predict", json={"input": DEFAULT_FEATURES})
    response.raise_for_status()
    return (perf_counter() - started) * 1000, 0.0, 0.0


async def classical_request(client: httpx.AsyncClient) -> tuple[float, float, float]:
    handshake_started = perf_counter()
    handshake_response = await client.get("/secure/handshake")
    handshake_response.raise_for_status()
    handshake = handshake_response.json()
    handshake_ms = (perf_counter() - handshake_started) * 1000
    rsa_key = serialization.load_pem_public_key(handshake["key_exchange_public_key"].encode())
    signing_key = serialization.load_pem_public_key(handshake["signing_public_key"].encode())
    session_key = os.urandom(32)
    encrypted_key = rsa_key.encrypt(session_key, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
    ))
    envelope = pack_envelope(session_key, json.dumps({"input": DEFAULT_FEATURES}).encode())
    started = perf_counter()
    response = await client.post("/secure/predict", json={
        "encrypted_key": b64(encrypted_key), "envelope": b64(envelope)
    })
    response.raise_for_status()
    rtt_ms = (perf_counter() - started) * 1000
    payload = response.json()
    encrypted_response = unb64(payload["envelope"])
    try:
        signing_key.verify(unb64(payload["signature"]), encrypted_response, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("Signature verification failed") from exc
    unpack_envelope(session_key, encrypted_response)  # verify AEAD integrity
    return rtt_ms, handshake_ms, float(payload["crypto_ms"])


async def run_cell(base_url: str, configuration: str, concurrency: int, requests: int, repetition: int) -> list[RequestMetric]:
    semaphore = asyncio.Semaphore(concurrency)
    metrics: list[RequestMetric] = []

    def resource_snapshot() -> tuple[float, int]:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        # macOS reports ru_maxrss in bytes; Linux reports KiB.
        rss = int(usage.ru_maxrss if os.uname().sysname == "Darwin" else usage.ru_maxrss * 1024)
        return usage.ru_utime + usage.ru_stime, rss

    async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
        async def one(index: int) -> None:
            async with semaphore:
                try:
                    rtt_ms, handshake_ms, crypto_ms = await (
                        control_request(client) if configuration == "control" else classical_request(client)
                    )
                    cpu_seconds, rss = resource_snapshot()
                    metrics.append(RequestMetric(configuration, concurrency, repetition, index, rtt_ms,
                        handshake_ms, crypto_ms, cpu_seconds, rss, True))
                except Exception as exc:
                    cpu_seconds, rss = resource_snapshot()
                    metrics.append(RequestMetric(configuration, concurrency, repetition, index, 0.0,
                        0.0, 0.0, cpu_seconds, rss, False, str(exc)))
        await asyncio.gather(*(one(index) for index in range(requests)))
    return metrics


async def main() -> None:
    parser = argparse.ArgumentParser(description="Record raw PQ-Shield benchmark metrics.")
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--configuration", choices=["control", "classical"], required=True)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--repetition", type=int, default=1)
    parser.add_argument("--output", type=Path, default=Path("results/raw/metrics.csv"))
    args = parser.parse_args()
    if min(args.concurrency, args.requests, args.repetition) < 1:
        parser.error("concurrency, requests, and repetition must be positive")
    metrics = await run_cell(args.url, args.configuration, args.concurrency, args.requests, args.repetition)
    write_metrics(metrics, args.output)
    print(f"Wrote {len(metrics)} records to {args.output} ({sum(metric.ok for metric in metrics)} successful)")


if __name__ == "__main__":
    asyncio.run(main())
