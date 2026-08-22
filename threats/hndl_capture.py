"""Threat Scenario 1 -- Harvest-Now-Decrypt-Later (HNDL) capture.

Simulates a passive adversary who logs every cryptographic artifact
(key-establishment blob, response ciphertext, signature) flowing over an
already-running protected server, without decrypting anything -- exactly
what an adversary archiving TLS-equivalent sessions for future decryption
would store. Confidentiality does not require any active interference; the
adversary just needs to see the wire bytes, which this script re-derives by
requesting the server's own byte-size breakdown (`X-Debug-Metrics: true`) on
every transaction rather than sniffing raw sockets, since the FastAPI JSON
already round-trips through base64 that a real network capture would show
in equivalent volume.

Distinguishes two things per H3 (see docs/DESIGN.md):
  - raw bytes an adversary would have to store per request, per config
  - whether that stored ciphertext is expected to become decryptable under
    a future CRQC (True only for the RSA/ECDSA key-establishment blob in
    Configuration A; False for ML-KEM ciphertexts in B/C, and independently
    False for the AES-256-GCM payload ciphertext in all three configs,
    since AES-256 itself is considered quantum-safe against Grover to a
    reasonable security margin -- only the *key establishment* is at risk
    under Shor's algorithm, not the symmetric payload encryption)

Usage:
    python -m threats.hndl_capture --configuration full-pqc \
        --url http://127.0.0.1:8000 --requests 1000 \
        --output results/hndl/full-pqc-hndl.csv
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

# Whether the key-establishment ciphertext becomes decryptable once a CRQC
# exists, per configuration. This is the core H3 distinction: "bytes
# stored" is not the same question as "bytes eventually decryptable".
KEX_DECRYPTABLE_UNDER_CRQC = {
    "classical": True,   # RSA-2048-OAEP broken by Shor's algorithm
    "hybrid": False,     # ML-KEM-768 -- lattice-based, not broken by Shor's algorithm
    "full_pqc": False,   # ML-KEM-768 -- same as above
}

# The AES-256-GCM payload ciphertext itself is not considered practically
# decryptable under a CRQC in any configuration (Grover's algorithm only
# halves AES's effective key length, from 256 to an effective ~128-bit
# security level, which remains computationally infeasible).
PAYLOAD_DECRYPTABLE_UNDER_CRQC = False


async def capture(config_name: str, base_url: str, n_requests: int) -> list[dict]:
    rows = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        for i in range(n_requests):
            row = await secure_predict_transaction(
                client, base_url, config_name, DEFAULT_FEATURES, debug_metrics=True
            )
            debug = row.get("debug") or {}
            kex_bytes = debug.get("kex_blob_bytes") or row.get("kex_blob_bytes") or 0
            payload_bytes = debug.get("response_ciphertext_bytes") or 0
            sig_bytes = debug.get("signature_bytes") or row.get("signature_bytes") or 0
            total_bytes = kex_bytes + payload_bytes + sig_bytes

            rows.append({
                "request_id": i,
                "config": config_name,
                "kex_algorithm": debug.get("kex_algorithm"),
                "sig_algorithm": debug.get("sig_algorithm"),
                "kex_blob_bytes": kex_bytes,
                "response_ciphertext_bytes": payload_bytes,
                "signature_bytes": sig_bytes,
                "total_bytes_stored": total_bytes,
                "kex_decryptable_under_future_crqc": KEX_DECRYPTABLE_UNDER_CRQC.get(config_name),
                "payload_decryptable_under_future_crqc": PAYLOAD_DECRYPTABLE_UNDER_CRQC,
                "error": row.get("error"),
            })
    return rows


def summarize(rows: list[dict], config_name: str) -> dict:
    ok_rows = [r for r in rows if not r["error"]]
    total_bytes = sum(r["total_bytes_stored"] for r in ok_rows)
    n = len(ok_rows)
    return {
        "config": config_name,
        "n_requests": len(rows),
        "n_ok": n,
        "total_bytes_stored": total_bytes,
        "bytes_per_request_mean": total_bytes / n if n else None,
        "kex_bytes_per_request": ok_rows[0]["kex_blob_bytes"] if ok_rows else None,
        "signature_bytes_per_request": ok_rows[0]["signature_bytes"] if ok_rows else None,
        "kex_decryptable_under_future_crqc": KEX_DECRYPTABLE_UNDER_CRQC.get(config_name),
        "projected_bytes_per_1000_requests": (total_bytes / n * 1000) if n else None,
    }


def main():
    parser = argparse.ArgumentParser(description="PQ-Shield HNDL passive capture")
    parser.add_argument("--configuration", required=True, choices=list(CONFIG_TO_MODULE_NAME.keys()))
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", default=None)
    args = parser.parse_args()

    config_name = CONFIG_TO_MODULE_NAME[args.configuration]
    if config_name == "control":
        raise SystemExit("HNDL capture is only meaningful for a protected configuration (not control).")

    rows = asyncio.run(capture(config_name, args.url, args.requests))

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    summary = summarize(rows, config_name)
    summary_path = args.summary_output or (os.path.splitext(args.output)[0] + "-summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
