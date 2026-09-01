"""Primitive-level micro-benchmark of the raw cryptographic operations, in the
same units published benchmarks use (operations per second, and microseconds
per operation).

Purpose: PQ-Shield's headline results are *application-level* (end-to-end RTT
of an inference API under concurrency). Those numbers cannot be compared
directly against anything in the literature, because no published work
benchmarks this workload. That is the novelty claim -- but it also means a
reviewer has no external anchor for the numbers.

This module supplies that anchor. It measures the same primitive operations
that liboqs' own `speed_kem` / `speed_sig` tools and essentially every
published PQC benchmark measure (keygen, encaps, decaps, sign, verify), on
whatever host the paper's results were collected on. That gives three things:

  1. A directly comparable figure: "on our host, ML-KEM-768 encapsulation runs
     at N ops/s" sits alongside published per-platform figures in the same units.
  2. A calibration factor: the ratio between this host's primitive throughput
     and a published platform's quantifies how fast the benchmarking host is,
     letting a reader mentally rescale the application-level results.
  3. Qualitative-ordering checks that must hold on *any* correct
     implementation regardless of hardware (see EXPECTED_QUALITATIVE_ORDERINGS
     in validation/reference_data.py). These are falsifiable and
     hardware-independent, so a failure here is a genuine bug, not a slow machine.

Run:
    python -m validation.primitive_bench
    python -m validation.primitive_bench --iterations 2000 --output results/validation/primitive_bench.json
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from crypto.oqs_adapter import MLDSA65, MLKEM768
from validation.reference_data import EXPECTED_QUALITATIVE_ORDERINGS, PUBLISHED_THROUGHPUT

_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
MESSAGE = b"pq-shield primitive benchmark message"


def _time_op(fn, iterations: int, warmup: int = 0) -> dict:
    """Times `fn` over `iterations` calls, discarding `warmup` leading calls.

    Reports median and p95 per-operation latency alongside the mean-derived
    throughput, because rejection-sampling schemes such as ML-DSA have a
    right-skewed signing distribution -- a mean alone hides that tail, which
    is exactly the property FIPS 204's Fiat-Shamir-with-Aborts construction
    creates and which the paper should report honestly.
    """
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1e6)  # microseconds
    samples.sort()
    mean_us = statistics.fmean(samples)
    return {
        "iterations": iterations,
        "mean_us": mean_us,
        "median_us": statistics.median(samples),
        "stdev_us": statistics.stdev(samples) if len(samples) > 1 else 0.0,
        "p95_us": samples[int(len(samples) * 0.95) - 1],
        "p99_us": samples[int(len(samples) * 0.99) - 1],
        "min_us": samples[0],
        "max_us": samples[-1],
        "ops_per_second": 1e6 / mean_us if mean_us > 0 else None,
    }


def bench_ml_kem_768(iterations: int) -> dict:
    kp = MLKEM768.keypair()
    ct, _ = MLKEM768.encaps(kp.public_key)
    return {
        "keygen": _time_op(lambda: MLKEM768.keypair(), iterations, warmup=10),
        "encaps": _time_op(lambda: MLKEM768.encaps(kp.public_key), iterations, warmup=10),
        "decaps": _time_op(lambda: MLKEM768.decaps(ct, kp.secret_key), iterations, warmup=10),
    }


def bench_ml_dsa_65(iterations: int) -> dict:
    kp = MLDSA65.keypair()
    sig = MLDSA65.sign(MESSAGE, kp.secret_key)
    return {
        "keygen": _time_op(lambda: MLDSA65.keypair(), iterations, warmup=10),
        "sign": _time_op(lambda: MLDSA65.sign(MESSAGE, kp.secret_key), iterations, warmup=10),
        "verify": _time_op(lambda: MLDSA65.verify(MESSAGE, sig, kp.public_key), iterations, warmup=10),
    }


def bench_classical(iterations: int, keygen_iterations: int | None = None) -> dict:
    """RSA-2048 and ECDSA P-256 baselines.

    RSA key generation is deliberately given a much smaller iteration count:
    it is probabilistic prime search, costs tens of milliseconds per call, and
    has enormous variance. That cost is precisely the mechanism behind
    PQ-Shield's high-concurrency availability finding, so it is measured
    rather than skipped -- just with a sample size that keeps the benchmark
    tractable.
    """
    keygen_iterations = keygen_iterations or max(5, iterations // 100)

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub = rsa_key.public_key()
    secret = os.urandom(32)
    rsa_ct = rsa_pub.encrypt(secret, _OAEP)

    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pub = ec_key.public_key()
    ec_sig = ec_key.sign(MESSAGE, ec.ECDSA(hashes.SHA256()))

    def _ec_verify():
        try:
            ec_pub.verify(ec_sig, MESSAGE, ec.ECDSA(hashes.SHA256()))
        except Exception:
            pass

    return {
        "rsa2048_keygen": _time_op(
            lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
            keygen_iterations, warmup=1,
        ),
        "rsa2048_oaep_encrypt": _time_op(lambda: rsa_pub.encrypt(secret, _OAEP), iterations, warmup=10),
        "rsa2048_oaep_decrypt": _time_op(lambda: rsa_key.decrypt(rsa_ct, _OAEP), iterations, warmup=10),
        "ecdsa_p256_keygen": _time_op(lambda: ec.generate_private_key(ec.SECP256R1()), iterations, warmup=10),
        "ecdsa_p256_sign": _time_op(
            lambda: ec_key.sign(MESSAGE, ec.ECDSA(hashes.SHA256())), iterations, warmup=10,
        ),
        "ecdsa_p256_verify": _time_op(_ec_verify, iterations, warmup=10),
    }


def check_orderings(kem: dict, sig: dict, classical: dict) -> list[dict]:
    """Evaluates the hardware-independent qualitative claims. A failure here
    indicates a real implementation problem, not merely a slow host."""
    results = []

    results.append({
        "claim": EXPECTED_QUALITATIVE_ORDERINGS[0]["claim"],
        "holds": sig["verify"]["mean_us"] < sig["sign"]["mean_us"],
        "evidence": {
            "ml_dsa_65_sign_mean_us": sig["sign"]["mean_us"],
            "ml_dsa_65_verify_mean_us": sig["verify"]["mean_us"],
            "sign_p99_us": sig["sign"]["p99_us"],
            "sign_p99_over_median": (
                sig["sign"]["p99_us"] / sig["sign"]["median_us"] if sig["sign"]["median_us"] else None
            ),
        },
        "rationale": EXPECTED_QUALITATIVE_ORDERINGS[0]["rationale"],
        "source": EXPECTED_QUALITATIVE_ORDERINGS[0]["source"],
    })

    results.append({
        "claim": EXPECTED_QUALITATIVE_ORDERINGS[2]["claim"],
        "holds": kem["keygen"]["mean_us"] < classical["rsa2048_keygen"]["mean_us"],
        "evidence": {
            "ml_kem_768_keygen_mean_us": kem["keygen"]["mean_us"],
            "rsa2048_keygen_mean_us": classical["rsa2048_keygen"]["mean_us"],
            "speedup_factor": (
                classical["rsa2048_keygen"]["mean_us"] / kem["keygen"]["mean_us"]
                if kem["keygen"]["mean_us"] else None
            ),
        },
        "rationale": EXPECTED_QUALITATIVE_ORDERINGS[2]["rationale"],
        "source": EXPECTED_QUALITATIVE_ORDERINGS[2]["source"],
    })

    results.append({
        "claim": "ML-DSA-65 verification is not slower than ECDSA P-256 verification (H4)",
        "holds": sig["verify"]["mean_us"] <= classical["ecdsa_p256_verify"]["mean_us"],
        "evidence": {
            "ml_dsa_65_verify_mean_us": sig["verify"]["mean_us"],
            "ecdsa_p256_verify_mean_us": classical["ecdsa_p256_verify"]["mean_us"],
            "ratio_mldsa_over_ecdsa": (
                sig["verify"]["mean_us"] / classical["ecdsa_p256_verify"]["mean_us"]
                if classical["ecdsa_p256_verify"]["mean_us"] else None
            ),
        },
        "rationale": (
            "This is PQ-Shield's own H4. It is listed here as a primitive-level check so the "
            "application-level result can be corroborated at the algorithm level on the same host."
        ),
        "source": "PQ-Shield docs/DESIGN.md H4; cf. Schemitt et al. (2025) on ML-DSA verification speed.",
    })

    return results


def calibration_vs_published(kem: dict) -> list[dict]:
    """Ratio of this host's ML-KEM-768 throughput to published per-platform
    figures. Not a correctness check -- a scale factor that lets a reader
    rescale the application-level results to hardware they know."""
    rows = []
    for pub in PUBLISHED_THROUGHPUT:
        op = pub.operation
        if op not in kem:
            continue
        measured = kem[op]["ops_per_second"]
        rows.append({
            "algorithm": pub.algorithm,
            "operation": op,
            "this_host_ops_per_second": measured,
            "published_platform": pub.platform,
            "published_ops_per_second": pub.ops_per_second,
            "this_host_relative_speed": measured / pub.ops_per_second if pub.ops_per_second else None,
            "source": pub.source,
        })
    return rows


def run_all(iterations: int) -> dict:
    kem = bench_ml_kem_768(iterations)
    sig = bench_ml_dsa_65(iterations)
    classical = bench_classical(iterations)
    return {
        "iterations": iterations,
        "ml_kem_768": kem,
        "ml_dsa_65": sig,
        "classical": classical,
        "qualitative_ordering_checks": check_orderings(kem, sig, classical),
        "calibration_vs_published": calibration_vs_published(kem),
    }


def main():
    parser = argparse.ArgumentParser(description="PQ-Shield primitive-level micro-benchmark")
    parser.add_argument("--iterations", type=int, default=300)
    parser.add_argument("--output", default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    results = run_all(args.iterations)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)

    if args.json:
        print(json.dumps(results, indent=2))
        return

    print("=" * 82)
    print(f"PQ-Shield primitive-level benchmark ({args.iterations} iterations per operation)")
    print("=" * 82)
    print(f"{'operation':<28}{'mean us':>11}{'median us':>12}{'p99 us':>11}{'ops/sec':>14}")
    print("-" * 82)
    for group, label in (("ml_kem_768", "ML-KEM-768"), ("ml_dsa_65", "ML-DSA-65"), ("classical", "Classical")):
        print(f"  {label}")
        for op, stats in results[group].items():
            print(f"    {op:<24}{stats['mean_us']:>11.1f}{stats['median_us']:>12.1f}"
                  f"{stats['p99_us']:>11.1f}{stats['ops_per_second']:>14,.0f}")

    print("\nHardware-independent ordering checks")
    print("-" * 82)
    for c in results["qualitative_ordering_checks"]:
        print(f"  [{'HOLDS' if c['holds'] else 'FAILS'}] {c['claim']}")
        for k, v in c["evidence"].items():
            if isinstance(v, float):
                print(f"           {k}: {v:,.2f}")

    print("\nCalibration against published ML-KEM-768 figures (scale factor, not a check)")
    print("-" * 82)
    for r in results["calibration_vs_published"]:
        print(f"  {r['operation']:<8} this host {r['this_host_ops_per_second']:>10,.0f} ops/s  vs  "
              f"{r['published_platform']:<34} {r['published_ops_per_second']:>10,.0f} ops/s  "
              f"({r['this_host_relative_speed']:.2f}x)")


if __name__ == "__main__":
    main()
