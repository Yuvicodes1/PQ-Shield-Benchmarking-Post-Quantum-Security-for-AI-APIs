"""Drives N protected transactions through a running threats.mitm_harness
proxy and records, per transaction, whether tampering was detected and how
long detection took -- answering RQ4: does active tampering get caught,
and does the signature scheme (ECDSA vs. ML-DSA-65) change how fast?

Detection can happen at one of two layers, which this script distinguishes:
  - AEAD layer: AES-GCM authentication tag check fails during response
    decryption (`aead_decrypt` raises AEADError) -- this is what actually
    catches a tampered *ciphertext* in practice, before signature
    verification is ever reached.
  - Signature layer: AES-GCM decryption succeeds (i.e. the ciphertext
    field was untouched) but `client.verify()` returns False -- this is
    what catches a tampered *signature* field specifically, and is the
    number that isolates ECDSA vs. ML-DSA-65 verification behavior for H4.

Also runs an equal number of *untampered* control transactions through the
same proxy (tamper-probability=0 path is driven by a second server-side
config) so detection-latency numbers can be compared like-for-like against
a non-adversarial baseline, isolating "cost of tampering" from "cost of
going through an extra proxy hop".

Usage:
    python -m threats.mitm_experiment --configuration full-pqc \
        --proxy-url http://127.0.0.1:8080 --requests 100 \
        --tamper-target ciphertext \
        --output results/mitm/full-pqc-mitm-ciphertext.csv
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os

import httpx

from api.secure_client import secure_predict_transaction
from bench.runner import DEFAULT_FEATURES, CONFIG_TO_MODULE_NAME


async def run(config_name: str, proxy_url: str, n_requests: int, tamper_target: str) -> list[dict]:
    rows = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        for i in range(n_requests):
            row = await secure_predict_transaction(
                client, proxy_url, config_name, DEFAULT_FEATURES, debug_metrics=True
            )
            detected = False
            detection_layer = None
            detection_ms = None

            if row.get("error") and "AEAD authentication failed" in str(row.get("error")):
                detected = True
                detection_layer = "aead_ciphertext"
                detection_ms = row.get("rtt_ms")  # decrypt happens right after the HTTP round trip
            elif row.get("valid_signature") is False:
                detected = True
                detection_layer = "signature"
                detection_ms = row.get("verify_ms")
            elif row.get("error"):
                detection_layer = "transport_error"

            rows.append({
                "request_id": i,
                "config": config_name,
                "tamper_target": tamper_target,
                "tampered_by_proxy": True,
                "detected": detected,
                "detection_layer": detection_layer,
                "detection_ms": detection_ms,
                "rtt_ms": row.get("rtt_ms"),
                "verify_ms": row.get("verify_ms"),
                "valid_signature": row.get("valid_signature"),
                "error": row.get("error"),
            })
    return rows


def summarize(rows: list[dict], config_name: str, tamper_target: str) -> dict:
    n = len(rows)
    n_detected = sum(1 for r in rows if r["detected"])
    detect_times = [r["detection_ms"] for r in rows if r["detection_ms"] is not None]
    return {
        "config": config_name,
        "tamper_target": tamper_target,
        "n_requests": n,
        "n_detected": n_detected,
        "detection_rate": n_detected / n if n else None,
        "detection_ms_mean": sum(detect_times) / len(detect_times) if detect_times else None,
        "detection_ms_min": min(detect_times) if detect_times else None,
        "detection_ms_max": max(detect_times) if detect_times else None,
        "verdict": "ALL TAMPERED RESPONSES REJECTED" if n_detected == n and n > 0 else "GAP DETECTED -- INVESTIGATE",
    }


def main():
    parser = argparse.ArgumentParser(description="PQ-Shield MITM tamper-detection experiment")
    parser.add_argument("--configuration", required=True, choices=list(CONFIG_TO_MODULE_NAME.keys()))
    parser.add_argument("--proxy-url", required=True, help="URL of threats.mitm_harness proxy")
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--tamper-target", choices=["ciphertext", "signature"], default="ciphertext")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    config_name = CONFIG_TO_MODULE_NAME[args.configuration]
    if config_name == "control":
        raise SystemExit("MITM experiment requires a protected configuration (control has no signature).")

    rows = asyncio.run(run(config_name, args.proxy_url, args.requests, args.tamper_target))

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    summary = summarize(rows, config_name, args.tamper_target)
    summary_path = os.path.splitext(args.output)[0] + "-summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
