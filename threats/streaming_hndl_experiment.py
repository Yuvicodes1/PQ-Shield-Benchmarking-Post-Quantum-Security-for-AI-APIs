"""Threat Scenario 1, streaming variant -- Harvest-Now-Decrypt-Later (HNDL)
exposure for a token-by-token streamed response, as opposed to
threats/hndl_capture.py's single-shot classifier response.

WHY THIS IS A DIFFERENT EXPERIMENT FROM threats/hndl_capture.py
--------------------------------------------------------------------
threats/hndl_capture.py already establishes the core H3 finding for one
small, fixed-size response: an adversary who passively records the
key-establishment blob and the response ciphertext gets nothing usable
under Configuration B/C (ML-KEM-768 is not broken by Shor's algorithm) and
everything usable under Configuration A (RSA-2048 is). That experiment's
exposure is bounded and fixed-size by construction -- one small JSON reply.

What it does not capture is what actually changes for a streaming AI API:
**a single handshake's session key is established once and reused for
every chunk of a potentially long-running stream** (a multi-turn chat
session, an agent's full reasoning trace, a long completion). If that one
handshake is later broken, an adversary who was harvesting the whole
session doesn't just recover one small response -- they recover the
*entire* accumulated streamed content, and that content only grows the
longer the stream runs. This experiment demonstrates that scaling
relationship empirically: harvestable bytes vs. response length, by
configuration.

The finding this produces is **not a new vulnerability class** -- it is the
same Shor's-algorithm-breaks-RSA/ECDH threat threats/hndl_capture.py
already measures, made worse in direct proportion to how long the stream
runs, because streaming's whole design point (one handshake, many chunks)
is exactly what maximizes the payoff of harvesting a single broken
handshake.

WHAT AN HNDL ADVERSARY ACTUALLY NEEDS TO STORE
----------------------------------------------------
A passive adversary harvesting for future decryption needs the
key-establishment blob (`kex_blob`, sent once per session) and, for every
chunk, its `(nonce, ciphertext)` pair -- these are what confidentiality
depends on. **Signatures and chain hashes are deliberately excluded** from
this project's "bytes an HNDL adversary would store" figure: they exist for
authenticity/integrity, not confidentiality, and an eavesdropper gains
nothing towards decrypting content later by also storing them. They are
still captured and reported here, but under a separate label
("integrity/traffic-shape bytes") -- see the second finding below, which is
explicitly a *different* threat property and must not be summed into the
HNDL byte totals in any table or figure this module produces.

REUSED, NOT REDEFINED
--------------------------
KEX_DECRYPTABLE_UNDER_CRQC and PAYLOAD_DECRYPTABLE_UNDER_CRQC are imported
from threats/hndl_capture.py, not redefined here -- see that module's
docstring for the H3 rationale behind each value.

A SECOND, UNRELATED FINDING THIS CAPTURE ALSO SURFACES: TRAFFIC-SHAPE METADATA
-------------------------------------------------------------------------------
While capturing the data above, this script also records, for free, a
**distinct** threat property that has nothing to do with whether any
cryptography is ever broken: `per_chunk` and `hash_chain` both put one
wire-visible SSE event on *every* chunk (a signature, or a chain hash,
riding alongside that chunk's ciphertext), which reveals the exact chunk
count and inter-chunk arrival timing to a passive network observer with
*zero* cryptanalysis -- timing that plausibly correlates with generation
rate/content. `buffer_and_sign` reveals only one final event, with no
intermediate wire structure exposed during generation. This is a
**traffic-shape metadata exposure**, not a confidentiality/HNDL finding --
it is reported separately (`n_wire_events`, `wire_event_bytes_*` in the
per-row output, and `strategy_wire_event_profile` in the summary) and
should be read as a caveat on `hash_chain`'s otherwise-strong recommendation
from the earlier streaming-signature work (docs/STREAMING.md), not a
reversal of it: hash_chain still wins decisively on signature-byte cost and
still fully protects confidentiality; it simply also happens to reveal
stream cadence to a passive observer, exactly as much as per_chunk does and
strictly more than buffer_and_sign does.

Usage:
    # Against a single already-running server (matches threats/hndl_capture.py's style):
    python -m threats.streaming_hndl_experiment \
        --configuration full-pqc --url http://127.0.0.1:8000 \
        --max-tokens 50,200,500,2000 --output results/hndl/streaming/full-pqc-streaming-hndl.csv

    # Self-managed sweep across all three configs (starts/stops each server itself,
    # like threats/streaming_mitm_experiment.py):
    python -m threats.streaming_hndl_experiment \
        --configs classical,hybrid,full-pqc --max-tokens 50,200,500,2000
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import time

import httpx

from api.secure_client import _b64d, _b64e, do_handshake
from bench.orchestrator import REPO_ROOT, SERVER_MODULES, _start_server, _stop_server, _wait_healthy
from crypto.aead import GCM_NONCE_BYTES, aead_encrypt
from crypto.registry import get_client_crypto
from crypto.streaming import STRATEGY_NAMES
from threats.hndl_capture import KEX_DECRYPTABLE_UNDER_CRQC, PAYLOAD_DECRYPTABLE_UNDER_CRQC

DEFAULT_PROMPT = (
    "Summarize the key risks of migrating a production API to post-quantum "
    "cryptography, focusing on latency-sensitive workloads."
)

CONFIG_TO_CRYPTO_NAME = {"classical": "classical", "hybrid": "hybrid", "full-pqc": "full_pqc"}


async def capture_transaction(
    client: httpx.AsyncClient,
    base_url: str,
    config_name: str,
    strategy: str,
    max_tokens: int,
    chunk_size_tokens: int = 5,
    prompt: str = DEFAULT_PROMPT,
) -> dict:
    """Runs one real streaming transaction and returns exactly what a
    passive adversary observing the wire (no decryption, no verification)
    would have recorded, split into the two distinct categories described
    in the module docstring: confidentiality-relevant bytes (kex blob +
    per-chunk nonce/ciphertext) vs. integrity/traffic-shape bytes
    (signatures, chain hashes, and the raw count/size of wire events)."""
    client_crypto = get_client_crypto(config_name)
    result: dict = {
        "config": config_name, "strategy": strategy, "max_tokens": max_tokens,
        "chunk_size_tokens": chunk_size_tokens, "error": None,
        "kex_blob_bytes": None, "total_ciphertext_bytes": 0, "total_bytes_harvestable": None,
        "total_integrity_bytes": 0, "n_wire_events": 0, "n_chunks": 0,
        "wire_event_bytes_min": None, "wire_event_bytes_max": None, "wire_event_bytes_mean": None,
        "kex_decryptable_under_future_crqc": KEX_DECRYPTABLE_UNDER_CRQC.get(config_name),
        "payload_decryptable_under_future_crqc": PAYLOAD_DECRYPTABLE_UNDER_CRQC,
        "decryptable_bytes_under_future_crqc": None,
    }

    try:
        handshake_json, _ = await do_handshake(client, base_url)
        kex_public_key = _b64d(handshake_json["kex_public_key"])
        handshake_id = handshake_json["handshake_id"]
        est = client_crypto.establish(kex_public_key)
        result["kex_blob_bytes"] = len(est.kex_blob)  # sent once per session, regardless of stream length

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

        wire_event_sizes: list[int] = []

        async with client.stream("POST", f"{base_url}/secure/predict/stream", json=payload, timeout=120.0) as resp:
            if resp.status_code != 200:
                result["error"] = f"HTTP {resp.status_code}"
                return result

            async for line in resp.aiter_lines():
                if not line.startswith("data:"):
                    continue
                data = json.loads(line[len("data:"):].strip())
                kind = data.get("kind")
                if kind is None:
                    continue  # the trailing "event: done" bookkeeping line -- no crypto content

                # Confidentiality-relevant bytes: present on "chunk" and
                # "final_buffered" (both carry a nonce + ciphertext).
                # "final_chain" carries neither -- only a hash and a signature.
                ciphertext_bytes = 0
                if "nonce" in data and "ciphertext" in data:
                    ciphertext_bytes = len(_b64d(data["nonce"])) + len(_b64d(data["ciphertext"]))
                    result["total_ciphertext_bytes"] += ciphertext_bytes

                # Integrity-only bytes: signature (per_chunk, final_buffered,
                # final_chain) and/or chain_hash (hash_chain's per-chunk
                # events) -- confidentiality does not depend on these.
                integrity_bytes = 0
                if data.get("signature"):
                    integrity_bytes += len(_b64d(data["signature"]))
                if data.get("chain_hash"):
                    integrity_bytes += len(_b64d(data["chain_hash"]))
                if data.get("final_chain_hash"):
                    integrity_bytes += len(_b64d(data["final_chain_hash"]))
                result["total_integrity_bytes"] += integrity_bytes

                if kind == "chunk":
                    result["n_chunks"] += 1
                result["n_wire_events"] += 1
                wire_event_sizes.append(ciphertext_bytes + integrity_bytes)

        result["total_bytes_harvestable"] = result["kex_blob_bytes"] + result["total_ciphertext_bytes"]
        result["decryptable_bytes_under_future_crqc"] = (
            result["total_ciphertext_bytes"] if KEX_DECRYPTABLE_UNDER_CRQC.get(config_name) else 0
        )
        if wire_event_sizes:
            result["wire_event_bytes_min"] = min(wire_event_sizes)
            result["wire_event_bytes_max"] = max(wire_event_sizes)
            result["wire_event_bytes_mean"] = sum(wire_event_sizes) / len(wire_event_sizes)

    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    return result


async def run_length_sweep(
    client: httpx.AsyncClient, base_url: str, config_name: str, strategy: str,
    max_tokens_values: list[int], chunk_size_tokens: int, prompt: str = DEFAULT_PROMPT,
) -> list[dict]:
    """The primary result: harvestable/decryptable bytes vs. response
    length, at one strategy (confidentiality exposure does not depend on
    signing strategy -- see run_strategy_independence_check for the
    empirical verification of that claim, not just an assumption of it)."""
    return [
        await capture_transaction(client, base_url, config_name, strategy, mt, chunk_size_tokens, prompt)
        for mt in max_tokens_values
    ]


async def run_strategy_independence_check(
    client: httpx.AsyncClient, base_url: str, config_name: str,
    max_tokens: int, chunk_size_tokens: int, prompt: str = DEFAULT_PROMPT,
) -> dict:
    """Runs all three strategies at one fixed response length and reports
    whether total_bytes_harvestable actually matched across them, rather
    than assuming strategy cannot affect confidentiality exposure.

    It is not exact by construction: buffer_and_sign encrypts the entire
    response as ONE AEAD envelope (one 12-byte nonce + one 16-byte GCM
    authentication tag, total), while per_chunk/hash_chain each encrypt many
    smaller chunks independently (their own 12-byte nonce + 16-byte tag PER
    chunk). For the same underlying generated content (the backend is a
    pure function of prompt + max_tokens, independent of strategy -- see
    model/streaming_backends/*.py), buffer_and_sign therefore has strictly
    fewer ciphertext-and-nonce bytes than per_chunk/hash_chain by exactly
    (n_chunks - 1) x (12 + 16) = (n_chunks - 1) x 28 bytes -- a real,
    structural property of "one big AEAD envelope" vs. "N small AEAD
    envelopes", not a bug. This function reports the actual byte deltas and
    explains them; it does not paper over a mismatch by asserting exact
    equality that the AEAD framing doesn't actually guarantee. (An earlier
    version of this function's own prediction only counted the 16-byte tag
    and not the 12-byte nonce per extra envelope, which underpredicted the
    delta by exactly 12 bytes per chunk -- caught by comparing against a
    live run rather than trusting the arithmetic unverified; see
    docs/STREAMING.md's HNDL section for the actual numbers this produced.)
    """
    rows = {}
    for strategy in STRATEGY_NAMES:
        rows[strategy] = await capture_transaction(
            client, base_url, config_name, strategy, max_tokens, chunk_size_tokens, prompt
        )

    harvestable = {s: rows[s]["total_bytes_harvestable"] for s in STRATEGY_NAMES if rows[s]["error"] is None}
    ciphertext = {s: rows[s]["total_ciphertext_bytes"] for s in STRATEGY_NAMES if rows[s]["error"] is None}
    n_chunks = {s: rows[s]["n_chunks"] for s in STRATEGY_NAMES if rows[s]["error"] is None}

    exact_match = len(set(harvestable.values())) <= 1 if harvestable else False

    # Expected AEAD-envelope-overhead delta, explained rather than hidden:
    # per_chunk/hash_chain each pay one extra 12-byte nonce + 16-byte GCM
    # tag per chunk; buffer_and_sign pays exactly one of each, total, for
    # the whole response.
    GCM_TAG_BYTES = 16
    overhead_per_extra_envelope = GCM_NONCE_BYTES + GCM_TAG_BYTES  # 28
    expected_deltas = {}
    if "buffer_and_sign" in ciphertext:
        base = ciphertext["buffer_and_sign"]
        for s in ("per_chunk", "hash_chain"):
            if s in ciphertext and s in n_chunks:
                expected_deltas[s] = (n_chunks[s] - 1) * overhead_per_extra_envelope
                expected_deltas[f"{s}_actual_delta"] = ciphertext[s] - base

    return {
        "config": config_name,
        "max_tokens": max_tokens,
        "chunk_size_tokens": chunk_size_tokens,
        "total_bytes_harvestable_by_strategy": harvestable,
        "total_ciphertext_bytes_by_strategy": ciphertext,
        "n_chunks_by_strategy": n_chunks,
        "exact_match_across_strategies": exact_match,
        "expected_vs_actual_aead_tag_overhead_delta": expected_deltas,
        "rows": rows,
    }


def summarize_length_sweep(rows: list[dict], config_name: str, strategy: str) -> dict:
    ok_rows = [r for r in rows if r["error"] is None]
    lengths = [r["max_tokens"] for r in ok_rows]
    harvestable = [r["total_bytes_harvestable"] for r in ok_rows]
    decryptable = [r["decryptable_bytes_under_future_crqc"] for r in ok_rows]

    # Monotonic scaling check: every step to a longer response must not
    # decrease harvestable bytes (this is the empirical "grows with every
    # additional token streamed" claim, not just an assertion of it).
    monotonic = all(harvestable[i] <= harvestable[i + 1] for i in range(len(harvestable) - 1))

    return {
        "config": config_name,
        "strategy": strategy,
        "n_lengths": len(ok_rows),
        "max_tokens_values": lengths,
        "total_bytes_harvestable_by_length": harvestable,
        "decryptable_bytes_under_future_crqc_by_length": decryptable,
        "kex_decryptable_under_future_crqc": KEX_DECRYPTABLE_UNDER_CRQC.get(config_name),
        "harvestable_bytes_monotonic_in_length": monotonic,
        "fraction_of_harvested_bytes_eventually_decryptable": (
            1.0 if KEX_DECRYPTABLE_UNDER_CRQC.get(config_name) else 0.0
        ),
    }


def _write_csv(rows: list[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    flat_rows = [{k: v for k, v in r.items() if k != "rows"} for r in rows]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(flat_rows[0].keys()))
        writer.writeheader()
        writer.writerows(flat_rows)


async def run_one_config(
    base_url: str, crypto_name: str, max_tokens_values: list[int], chunk_size_tokens: int,
    primary_strategy: str, prompt: str = DEFAULT_PROMPT,
) -> dict:
    """Runs the full experiment (length sweep + strategy-independence check)
    against an already-running server for one config. Used by both CLI modes."""
    async with httpx.AsyncClient(timeout=120.0) as client:
        sweep_rows = await run_length_sweep(
            client, base_url, crypto_name, primary_strategy, max_tokens_values, chunk_size_tokens, prompt
        )
        independence = await run_strategy_independence_check(
            client, base_url, crypto_name, min(max_tokens_values), chunk_size_tokens, prompt
        )
    return {
        "config": crypto_name,
        "primary_strategy": primary_strategy,
        "sweep_rows": sweep_rows,
        "sweep_summary": summarize_length_sweep(sweep_rows, crypto_name, primary_strategy),
        "strategy_independence": independence,
    }


def _print_report(result: dict) -> None:
    s = result["sweep_summary"]
    print(f"\n=== {result['config']} (strategy={result['primary_strategy']}) length sweep ===")
    print(f"{'max_tokens':>12}{'harvestable_bytes':>20}{'decryptable_bytes':>20}")
    for mt, hb, db in zip(s["max_tokens_values"], s["total_bytes_harvestable_by_length"],
                          s["decryptable_bytes_under_future_crqc_by_length"]):
        print(f"{mt:>12}{hb:>20}{db:>20}")
    print(f"kex_decryptable_under_future_crqc: {s['kex_decryptable_under_future_crqc']}")
    print(f"harvestable_bytes_monotonic_in_length: {s['harvestable_bytes_monotonic_in_length']}")
    print(f"fraction_of_harvested_bytes_eventually_decryptable: "
          f"{s['fraction_of_harvested_bytes_eventually_decryptable']:.0%}")

    ind = result["strategy_independence"]
    print(f"\n=== {result['config']} strategy-independence check (max_tokens={ind['max_tokens']}) ===")
    print("total_bytes_harvestable by strategy:", ind["total_bytes_harvestable_by_strategy"])
    print("exact_match_across_strategies:", ind["exact_match_across_strategies"])
    if ind["expected_vs_actual_aead_tag_overhead_delta"]:
        print("expected vs. actual AEAD-tag-overhead delta (bytes, vs. buffer_and_sign):",
              ind["expected_vs_actual_aead_tag_overhead_delta"])


def main():
    parser = argparse.ArgumentParser(description="PQ-Shield streaming HNDL exposure-scaling experiment")
    parser.add_argument("--configuration", choices=list(CONFIG_TO_CRYPTO_NAME.keys()),
                         help="Single config, against an already-running server at --url")
    parser.add_argument("--configs", default=None,
                         help="Comma-separated configs to sweep, starting/stopping each server itself "
                              "(alternative to --configuration + --url)")
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--max-tokens", default="50,200,500,2000", help="Comma-separated response lengths")
    parser.add_argument("--chunk-size-tokens", type=int, default=5)
    parser.add_argument("--strategy", default="per_chunk", choices=STRATEGY_NAMES,
                         help="Primary strategy for the length sweep (confidentiality exposure does not "
                              "depend on strategy -- see the strategy-independence check)")
    parser.add_argument("--output", default=None, help="CSV path for the length-sweep raw rows")
    parser.add_argument("--summary-output", default=None, help="JSON path for the full summary")
    parser.add_argument("--output-dir", default=os.path.join(REPO_ROOT, "results", "hndl", "streaming"))
    parser.add_argument("--log-dir", default=os.path.join(REPO_ROOT, "results", "server_logs"))
    args = parser.parse_args()

    max_tokens_values = [int(x.strip()) for x in args.max_tokens.split(",") if x.strip()]

    if args.configs:
        configs = [c.strip() for c in args.configs.split(",") if c.strip()]
        os.makedirs(args.output_dir, exist_ok=True)
        os.makedirs(args.log_dir, exist_ok=True)
        base_url = f"http://127.0.0.1:{args.port}"
        all_results = {}
        for config_key in configs:
            crypto_name = CONFIG_TO_CRYPTO_NAME[config_key]
            log_path = os.path.join(args.log_dir, f"streaming-hndl-server-{config_key}.log")
            print(f"\n=== Starting server: {config_key} ({SERVER_MODULES[config_key]}) ===", flush=True)
            proc = _start_server(config_key, args.port, log_path)
            try:
                _wait_healthy(base_url)
                print(f"Server healthy (pid={proc.pid}).", flush=True)
                result = asyncio.run(run_one_config(
                    base_url, crypto_name, max_tokens_values, args.chunk_size_tokens, args.strategy
                ))
                _print_report(result)
                all_results[crypto_name] = result

                _write_csv(result["sweep_rows"], os.path.join(args.output_dir, f"{crypto_name}-streaming-hndl.csv"))
                with open(os.path.join(args.output_dir, f"{crypto_name}-streaming-hndl-summary.json"), "w") as f:
                    json.dump(result["sweep_summary"], f, indent=2)
                with open(os.path.join(args.output_dir, f"{crypto_name}-strategy-independence.json"), "w") as f:
                    json.dump(
                        {k: v for k, v in result["strategy_independence"].items() if k != "rows"}, f, indent=2
                    )
            finally:
                print(f"Stopping server: {config_key}", flush=True)
                _stop_server(proc)
                time.sleep(1.0)
        return

    if not args.configuration:
        raise SystemExit("Pass either --configuration (single, already-running server) or --configs (sweep)")

    crypto_name = CONFIG_TO_CRYPTO_NAME[args.configuration]
    result = asyncio.run(run_one_config(
        args.url, crypto_name, max_tokens_values, args.chunk_size_tokens, args.strategy
    ))
    _print_report(result)

    if args.output:
        _write_csv(result["sweep_rows"], args.output)
    summary_path = args.summary_output or (
        os.path.splitext(args.output)[0] + "-summary.json" if args.output else None
    )
    if summary_path:
        with open(summary_path, "w") as f:
            json.dump(result["sweep_summary"], f, indent=2)


if __name__ == "__main__":
    main()
