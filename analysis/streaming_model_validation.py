"""Validates results/streaming/*.csv (bench/streaming_runner.py's output)
against an analytical model of signature cost derived from the primitive
constants NIST-KAT-verified in validation/nist_kat.py and measured in
validation/primitive_bench.py.

WHY THIS IS THE RIGHT VALIDATION, GIVEN NO EXTERNAL STREAMING BENCHMARK EXISTS
--------------------------------------------------------------------------------
There is no published external dataset measuring PQC signature overhead on
*streamed* AI responses. That absence is this project's own novelty claim --
if such a dataset existed, this work would be redundant. So "validate
against an external ground truth" is not achievable for the streaming
result the way it was for the primitives (validation/nist_kat.py, checked
against NIST's own ACVP vectors).

What is validated instead is the *measurement instrument itself*. The
streaming signing strategies in crypto/streaming.py implement pure,
deterministic arithmetic on top of primitives (ML-KEM-768, ML-DSA-65,
ECDSA-P256) that are already proven correct. Given the number of chunks a
transaction actually produced, the number of signatures each strategy
issues and the number of bytes each signature costs follow by construction,
not by measurement -- `per_chunk` signs once per chunk, `hash_chain` signs
once per checkpoint (or once total), `buffer_and_sign` signs once, full
stop. If this module's *predictions*, computed purely from that arithmetic
and the independently-measured primitive costs, match what the live
benchmark harness actually recorded, that proves the harness introduces no
unaccounted overhead, no double-counting, and no silent divergence between
what the strategy is supposed to do and what it measurably does.

This is the correct and defensible substitute for an external dataset --
not "we couldn't find ground truth so we made do," but "the ground truth
for a measurement-instrument validation is the arithmetic the instrument is
supposed to implement." State it this way in the paper's methodology
section, not as an apology.

WHAT "EXACT" MEANS HERE, AND WHERE IT GENUINELY CANNOT APPLY
----------------------------------------------------------------
Signature-byte totals are checked as tightly as each algorithm's own
encoding allows -- which is not uniformly "one fixed number per algorithm":

  ML-DSA-65 (full_pqc)   FIPS 204 specifies a fixed 3,309-byte signature,
                         confirmed byte-exact by validation/nist_kat.py.
                         Every ML-DSA-65 signature this project produces is
                         exactly 3,309 bytes, so `n_signatures x 3309` is
                         checked for EXACT equality against the measured
                         total. Any deviation is a real bug.

  ECDSA-P256 (classical, DER-encoded ECDSA signatures are NOT fixed-length --
  hybrid)                this is a property of the SEC1/RFC 3279 ASN.1
                         encoding (each of the two integers r, s gets an
                         extra leading 0x00 byte whenever its own top bit is
                         set), not an implementation quirk. The observed
                         range on this project's own measurements (and
                         validation/reference_data.py's CLASSICAL_REFERENCE
                         entry) is 70-72 bytes per signature. A single
                         scalar "sig_bytes" constant therefore cannot
                         predict an exact byte total for a multi-signature
                         strategy (`per_chunk` sums many independently
                         variable-length signatures) -- what CAN be checked
                         exactly is the *bound*: `n_signatures x 70` through
                         `n_signatures x 72` is an exact integer range with
                         no fitted tolerance, and a measured total outside
                         that range is still a real bug (e.g. a dropped or
                         duplicated signature). This is reported as a
                         distinct "bytes_in_range" check, not silently
                         folded into the same "bytes_exact" flag ML-DSA-65
                         gets, precisely so an ECDSA config's inherent
                         encoding variability is never mistaken for slack in
                         the validation.

Signing TIME is never checked for exact equality, by design -- ML-DSA-65's
Fiat-Shamir-with-Aborts rejection sampling gives it a genuinely
right-skewed distribution (see validation/primitive_bench.py), so a single
transaction's summed signing time is a statistical quantity, not an exact
one. The tolerance used here is not an arbitrary "close enough" -- it is
each algorithm's own measured p99/median ratio from
results/validation/primitive_bench.json, i.e. the same skew
primitive_bench.py already quantifies is reused as the acceptance window,
so a wide tolerance for ML-DSA-65 and a tight one for ECDSA both fall out
of the same measured data rather than being chosen by hand.

WHERE `n_chunks` COMES FROM
--------------------------------
Predictions are computed from each row's actually-recorded `n_chunks`, not
from `ceil(max_tokens / chunk_size_tokens)`. A real generation backend's
text pieces do not map 1:1 to a token count the synthetic backend's word-at-
a-time output does, so deriving `n_chunks` analytically from the configured
sweep parameters would produce mismatches that are artifacts of token
counting, not of the signing arithmetic under test. Reading the harness's
own recorded `n_chunks` and predicting only the *byte and timing
consequences* of that number is what actually isolates the claim being
validated: given N chunks, does the signing strategy cost what it should?

A related quirk, not a bug: `buffer_and_sign` rows always record
`n_chunks == 0`. This is because the client-side metrics counter in
api/secure_streaming_client.py only increments on `kind == "chunk"` SSE
events, and `buffer_and_sign` never emits one (crypto/streaming.py's
`BufferAndSignStrategy.add_chunk()` always returns None, buffering
internally until `finalize()`). The model does not use `n_chunks` for
`buffer_and_sign` at all -- it always predicts exactly 1 signature,
matching the table below -- so this is noted here to pre-empt it being
mistaken for missing data.

CHECKPOINT_INTERVAL: A KNOWN GAP IN THE CSV SCHEMA
--------------------------------------------------------
`bench/streaming_runner.py`'s CSV_FIELDS does not currently record
`checkpoint_interval`, and its own `_run_one()` never passes one through to
`run_streaming_transaction()` -- so every row bench.streaming_runner has
ever produced is implicitly `checkpoint_interval=None` (hash_chain signs
only once, at the end). This module reads the column if present (for a
future harness version that records it) and otherwise assumes None, but
flags in its output whether it had to assume this. If `hash_chain`
checkpointing is ever benchmarked, the CSV schema needs to grow that
column first, or this validator cannot distinguish a checkpointed
hash_chain row from a non-checkpointed one.

THE MODEL
-------------
For a transaction with a recorded `n_chunks` under signature scheme
producing `sig_bytes` bytes per signature (exact for ML-DSA-65; a
[min, max] range for ECDSA-P256):

    buffer_and_sign              -> 1 signature
    per_chunk                    -> n_chunks signatures
    hash_chain, no checkpoint    -> 1 signature
    hash_chain, checkpoint every -> floor(n_chunks / k) + 1 signatures
      k chunks

    expected_signature_bytes  = expected_signatures * sig_bytes  (or range)
    expected_signing_time_us  = expected_signatures * mean_sign_us(scheme)

Usage:
    python -m analysis.streaming_model_validation
    python -m analysis.streaming_model_validation --json
    python -m analysis.streaming_model_validation --output results/streaming_model_validation.json
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import os

import pandas as pd

from crypto.registry import get_server_crypto
from validation.reference_data import FIPS_204_ML_DSA_65

# ECDSA-P256 DER-encoded signature length bounds. Not a fitted/observed
# range -- these are the exact bounds SEC1/RFC 3279's ASN.1 DER encoding of
# an ECDSA-Sig-Value (two INTEGERs, each up to 33 bytes with an optional
# leading zero pad byte) can produce for a 256-bit curve, and match
# validation/reference_data.py's CLASSICAL_REFERENCE["ECDSA-P256"] note.
ECDSA_P256_DER_MIN_BYTES = 70
ECDSA_P256_DER_MAX_BYTES = 72

ML_DSA_65_SIGNATURE_BYTES = FIPS_204_ML_DSA_65.signature_bytes  # 3309, KAT-confirmed exact

# crypto/*.py's `sig_algorithm` string -> the primitive_bench.json key that
# has that scheme's measured signing-time distribution.
_SIG_ALGORITHM_TO_BENCH_KEY = {
    "ML-DSA-65": ("ml_dsa_65", "sign"),
    "ECDSA-P256-SHA256": ("classical", "ecdsa_p256_sign"),
}


def sig_algorithm_for_config(config_name: str) -> str:
    """Looks up which signature scheme a config actually signs with, from
    crypto/registry.py -- not hardcoded per strategy, so a future config
    change (or a classical/hybrid mixup) can't silently go unnoticed here."""
    return get_server_crypto(config_name).sig_algorithm


def load_primitive_bench(path: str) -> dict:
    if not os.path.isfile(path):
        raise SystemExit(
            f"{path} not found. Run `python -m validation.primitive_bench "
            f"--output {path}` first -- this module predicts signing time "
            f"from its measured mean_us figures."
        )
    with open(path) as f:
        return json.load(f)


def mean_sign_us_and_tolerance(sig_algorithm: str, primitive_bench: dict) -> tuple[float, float]:
    """Returns (mean_sign_us, tolerance_ratio) for one signature scheme.

    tolerance_ratio is that scheme's own measured p99_us / median_us from
    primitive_bench.json -- e.g. ML-DSA-65's Fiat-Shamir-with-Aborts
    rejection sampling gives it a wide, right-skewed tolerance; ECDSA's
    tight, close-to-constant-time signing gives it a narrow one. A
    predicted-vs-measured ratio is accepted if it falls within
    [1/tolerance_ratio, tolerance_ratio]."""
    group_key, op_key = _SIG_ALGORITHM_TO_BENCH_KEY[sig_algorithm]
    stats = primitive_bench[group_key][op_key]
    mean_us = stats["mean_us"]
    median_us = stats["median_us"]
    tolerance_ratio = (stats["p99_us"] / median_us) if median_us else 3.0
    return mean_us, tolerance_ratio


_SIG_ALGORITHM_TO_COLD_START_KEY = {
    "ML-DSA-65": "ml_dsa_65_sign",
    "ECDSA-P256-SHA256": "ecdsa_p256_sign",
}


def cold_start_ms_and_tolerance(sig_algorithm: str, primitive_bench: dict) -> tuple[float, float] | None:
    """Returns (cold_start_mean_ms, tolerance_ratio) for one scheme's FIRST
    sign call in a fresh process, or None if primitive_bench.json predates
    validation.primitive_bench.bench_cold_start_signing() (older files won't
    have the "cold_start_signing" key -- this degrades gracefully rather
    than crashing on them).

    WHY THIS EXISTS: diagnosing this project's own streaming-signing-time
    validation found that ECDSA (via the `cryptography` library's
    lazily-initialized OpenSSL backend) pays a real, one-time ~8ms cost on
    the first ECDSA operation of a process -- confirmed by direct repeated
    measurement (validation/primitive_bench.py's module docstring has the
    full diagnostic history) -- while ML-DSA-65 (liboqs, no external
    backend to lazily load) does not. A warm-loop mean (mean_sign_us_and_tolerance
    above) is the right predictor for a signature produced after other
    signing has already happened in the same process; it is the WRONG
    predictor for literally the first ECDSA signature a process ever
    produces, which is exactly what `buffer_and_sign` is when it's the
    first strategy tried against a freshly-started server (bench/streaming_runner.py's
    default strategy order starts with buffer_and_sign). See
    docs/STREAMING.md's "Validating the measurement instrument itself" for
    the full before/after comparison this produced.

    Tolerance here is tighter than the warm-loop one deliberately: the
    cold-start cost is a fixed one-time library-initialization cost, not a
    rejection-sampling-driven distribution, so it should be far more
    consistent run to run than ML-DSA's signing time is -- floored at 1.5x
    in case a small sample (n=8 processes by default) understates real
    variance."""
    cold = primitive_bench.get("cold_start_signing")
    if not cold:
        return None
    key = _SIG_ALGORITHM_TO_COLD_START_KEY[sig_algorithm]
    if key not in cold:
        return None
    stats = cold[key]
    mean_ms = stats["mean_ms"]
    tolerance_ratio = max(1.5, (stats["max_ms"] / mean_ms) if mean_ms else 1.5)
    return mean_ms, tolerance_ratio


def expected_signature_count(strategy: str, n_chunks: int, checkpoint_interval: int | None) -> int:
    if strategy == "buffer_and_sign":
        return 1
    if strategy == "per_chunk":
        return max(0, int(n_chunks))
    if strategy == "hash_chain":
        if not checkpoint_interval or checkpoint_interval <= 0:
            return 1
        return (int(n_chunks) // int(checkpoint_interval)) + 1
    raise ValueError(f"Unknown strategy {strategy!r}")


def expected_signature_bytes(sig_algorithm: str, n_signatures: int) -> tuple[int, int]:
    """Returns (min_bytes, max_bytes) inclusive -- equal for ML-DSA-65
    (fixed-length), a genuine range for ECDSA-P256 (variable-length DER)."""
    if sig_algorithm == "ML-DSA-65":
        total = n_signatures * ML_DSA_65_SIGNATURE_BYTES
        return total, total
    if sig_algorithm == "ECDSA-P256-SHA256":
        return n_signatures * ECDSA_P256_DER_MIN_BYTES, n_signatures * ECDSA_P256_DER_MAX_BYTES
    raise ValueError(f"Unknown signature algorithm {sig_algorithm!r}")


def validate_row(row: dict, primitive_bench: dict) -> dict:
    config = row["config"]
    strategy = row["strategy"]
    n_chunks = int(row["n_chunks"])
    checkpoint_interval = row.get("checkpoint_interval")
    checkpoint_interval = int(checkpoint_interval) if checkpoint_interval not in (None, "", "nan") and not (
        isinstance(checkpoint_interval, float) and math.isnan(checkpoint_interval)
    ) else None
    assumed_no_checkpoint = "checkpoint_interval" not in row

    sig_algorithm = sig_algorithm_for_config(config)
    measured_bytes = int(row["total_signature_bytes"])
    measured_signing_ms = float(row["total_signing_ms"])

    expected_sigs = expected_signature_count(strategy, n_chunks, checkpoint_interval)
    bytes_min, bytes_max = expected_signature_bytes(sig_algorithm, expected_sigs)
    bytes_exact_scheme = sig_algorithm == "ML-DSA-65"
    bytes_ok = bytes_min <= measured_bytes <= bytes_max

    mean_sign_us, tolerance_ratio = mean_sign_us_and_tolerance(sig_algorithm, primitive_bench)
    predicted_signing_ms = expected_sigs * mean_sign_us / 1000.0
    if predicted_signing_ms > 0:
        timing_ratio = measured_signing_ms / predicted_signing_ms
    else:
        timing_ratio = 1.0 if measured_signing_ms == 0 else float("inf")
    timing_ok = (1.0 / tolerance_ratio) <= timing_ratio <= tolerance_ratio if predicted_signing_ms > 0 else (
        measured_signing_ms == 0
    )

    # Cold-start-corrected timing prediction, applicable only to
    # buffer_and_sign: the one strategy that is (by bench/streaming_runner.py's
    # default strategy order) typically the FIRST ECDSA/ML-DSA sign call a
    # freshly-started server process performs. per_chunk (~100 signatures,
    # dominated by warm-loop-like repeated calls) and hash_chain (typically
    # run after buffer_and_sign against an already-warmed process) are left
    # on the warm-loop baseline above -- applying the cold-start correction
    # there would overclaim a mechanism not confirmed for those cases. See
    # cold_start_ms_and_tolerance()'s docstring for the full rationale.
    predicted_signing_ms_cold_start = None
    timing_ratio_cold_start = None
    timing_ok_cold_start = None
    tolerance_ratio_cold_start = None
    if strategy == "buffer_and_sign":
        cold = cold_start_ms_and_tolerance(sig_algorithm, primitive_bench)
        if cold is not None:
            cold_mean_ms, tolerance_ratio_cold_start = cold
            predicted_signing_ms_cold_start = expected_sigs * cold_mean_ms
            timing_ratio_cold_start = (
                measured_signing_ms / predicted_signing_ms_cold_start if predicted_signing_ms_cold_start > 0
                else float("inf")
            )
            timing_ok_cold_start = (
                (1.0 / tolerance_ratio_cold_start) <= timing_ratio_cold_start <= tolerance_ratio_cold_start
            )

    return {
        "config": config,
        "strategy": strategy,
        "max_tokens": row.get("max_tokens"),
        "chunk_size_tokens": row.get("chunk_size_tokens"),
        "repetition": row.get("repetition"),
        "n_chunks": n_chunks,
        "checkpoint_interval": checkpoint_interval,
        "checkpoint_interval_assumed": assumed_no_checkpoint,
        "sig_algorithm": sig_algorithm,
        "expected_signatures": expected_sigs,
        "expected_bytes_min": bytes_min,
        "expected_bytes_max": bytes_max,
        "expected_bytes_exact_scheme": bytes_exact_scheme,
        "measured_bytes": measured_bytes,
        "bytes_ok": bool(bytes_ok),
        "mean_sign_us": mean_sign_us,
        "tolerance_ratio": tolerance_ratio,
        "predicted_signing_ms": predicted_signing_ms,
        "measured_signing_ms": measured_signing_ms,
        "timing_ratio": timing_ratio,
        "timing_ok": bool(timing_ok),
        "predicted_signing_ms_cold_start": predicted_signing_ms_cold_start,
        "timing_ratio_cold_start": timing_ratio_cold_start,
        "timing_ok_cold_start": timing_ok_cold_start,
        "tolerance_ratio_cold_start": tolerance_ratio_cold_start,
    }


def load_streaming_raw(streaming_dir: str) -> pd.DataFrame:
    paths = sorted(glob.glob(os.path.join(streaming_dir, "*.csv")))
    if not paths:
        raise SystemExit(f"No CSV files found under {streaming_dir}. Run bench.streaming_runner first.")
    frames = [pd.read_csv(p) for p in paths]
    return pd.concat(frames, ignore_index=True)


def run_validation(streaming_dir: str, primitive_bench_path: str) -> dict:
    df = load_streaming_raw(streaming_dir)
    primitive_bench = load_primitive_bench(primitive_bench_path)

    ok = df[df["error"].isna() | (df["error"] == "")]
    n_excluded = len(df) - len(ok)

    rows = [validate_row(r, primitive_bench) for r in ok.to_dict("records")]

    # "Best applicable" timing check: use the cold-start baseline where it
    # applies (buffer_and_sign) and confirmed applicable, the warm-loop
    # baseline everywhere else -- this is the fair, corrected comparison;
    # `timing_ok` (warm-loop-only) is left untouched alongside it so the
    # "before" number stays visible, not silently replaced.
    for r in rows:
        r["timing_ok_best"] = r["timing_ok_cold_start"] if r["timing_ok_cold_start"] is not None else r["timing_ok"]

    n_bytes_ok = sum(r["bytes_ok"] for r in rows)
    n_timing_ok = sum(r["timing_ok"] for r in rows)
    n_timing_ok_best = sum(r["timing_ok_best"] for r in rows)

    by_strategy_config = {}
    for r in rows:
        key = f"{r['config']}/{r['strategy']}"
        by_strategy_config.setdefault(key, []).append(r)

    per_group = []
    for key, group in sorted(by_strategy_config.items()):
        per_group.append({
            "group": key,
            "n_rows": len(group),
            "bytes_ok": sum(g["bytes_ok"] for g in group),
            "bytes_exact_scheme": group[0]["expected_bytes_exact_scheme"],
            "timing_ok": sum(g["timing_ok"] for g in group),
            "timing_ratio_min": min(g["timing_ratio"] for g in group),
            "timing_ratio_max": max(g["timing_ratio"] for g in group),
            "tolerance_ratio": group[0]["tolerance_ratio"],
            "timing_ok_best": sum(g["timing_ok_best"] for g in group),
            "used_cold_start_baseline": any(g["timing_ratio_cold_start"] is not None for g in group),
        })

    return {
        "rows": rows,
        "per_group": per_group,
        "summary": {
            "total_rows": len(df),
            "excluded_error_rows": int(n_excluded),
            "validated_rows": len(rows),
            "bytes_ok": int(n_bytes_ok),
            "bytes_all_ok": n_bytes_ok == len(rows),
            "timing_ok": int(n_timing_ok),
            "timing_all_ok": n_timing_ok == len(rows),
            "timing_ok_best": int(n_timing_ok_best),
            "timing_all_ok_best": n_timing_ok_best == len(rows),
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="Validate results/streaming/*.csv against an analytical signature-cost model"
    )
    parser.add_argument("--streaming-dir", default="results/streaming")
    parser.add_argument("--primitive-bench", default="results/validation/primitive_bench.json")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--output", default=None, help="Write JSON to this path as well")
    args = parser.parse_args()

    results = run_validation(args.streaming_dir, args.primitive_bench)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)

    if args.json:
        print(json.dumps(results, indent=2))
        return

    print("=" * 92)
    print("Streaming signature-cost model validation (vs. results/streaming/*.csv)")
    print("=" * 92)
    s = results["summary"]
    print(f"{s['validated_rows']} rows validated ({s['excluded_error_rows']} excluded for a non-empty error)\n")

    print(f"{'group':<28}{'rows':>6}{'bytes ok':>10}{'scheme':>12}{'timing(warm)':>13}"
          f"{'ratio range':>16}{'tol':>7}{'timing(best)':>13}{'baseline':>11}")
    print("-" * 92)
    for g in results["per_group"]:
        scheme = "exact" if g["bytes_exact_scheme"] else "range"
        ratio_range = f"{g['timing_ratio_min']:.2f}-{g['timing_ratio_max']:.2f}x"
        baseline = "cold-start" if g["used_cold_start_baseline"] else "warm-loop"
        print(f"{g['group']:<28}{g['n_rows']:>6}{g['bytes_ok']:>6}/{g['n_rows']:<3}{scheme:>12}"
              f"{g['timing_ok']:>6}/{g['n_rows']:<5}{ratio_range:>16}{g['tolerance_ratio']:>6.2f}x"
              f"{g['timing_ok_best']:>6}/{g['n_rows']:<5}{baseline:>11}")

    print()
    if not s["bytes_all_ok"]:
        print("BYTE MISMATCHES FOUND -- investigate before trusting the streaming numbers:")
        for r in results["rows"]:
            if not r["bytes_ok"]:
                print(f"  {r['config']}/{r['strategy']} n_chunks={r['n_chunks']} "
                      f"expected=[{r['expected_bytes_min']},{r['expected_bytes_max']}] "
                      f"measured={r['measured_bytes']}")

    if any(r["timing_ratio_cold_start"] is not None for r in results["rows"]):
        print("Cold-start-corrected rows (buffer_and_sign) -- see docs/STREAMING.md "
              "'Validating the measurement instrument itself' for why this baseline applies here:")
        for r in results["rows"]:
            if r["timing_ratio_cold_start"] is not None:
                print(f"  {r['config']}/{r['strategy']}: warm-loop ratio={r['timing_ratio']:.2f}x "
                      f"(tol {r['tolerance_ratio']:.2f}x, {'OK' if r['timing_ok'] else 'FAIL'})  "
                      f"-> cold-start ratio={r['timing_ratio_cold_start']:.2f}x "
                      f"(tol {r['tolerance_ratio_cold_start']:.2f}x, "
                      f"{'OK' if r['timing_ok_cold_start'] else 'FAIL'})")
        print()

    print("=" * 92)
    print(f"Bytes:              {s['bytes_ok']}/{s['validated_rows']} rows within expected bound"
          f"{'  -- ALL OK' if s['bytes_all_ok'] else '  -- MISMATCHES PRESENT'}")
    print(f"Timing (warm-loop): {s['timing_ok']}/{s['validated_rows']} rows within tolerance"
          f"{'  -- ALL OK' if s['timing_all_ok'] else '  -- OUT OF TOLERANCE ROWS PRESENT'}")
    print(f"Timing (best applicable baseline): {s['timing_ok_best']}/{s['validated_rows']} rows within tolerance"
          f"{'  -- ALL OK' if s['timing_all_ok_best'] else '  -- OUT OF TOLERANCE ROWS PRESENT'}")
    print("=" * 92)


if __name__ == "__main__":
    main()
