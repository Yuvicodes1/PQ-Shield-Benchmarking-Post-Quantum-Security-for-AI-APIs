"""Builds the composite security/performance trade-off matrix (design doc
Phase 6, "Layer 6"). The composite score formula is:

    composite_score(config, concurrency) =
        w_sec * security_score(config) - w_perf * normalized_latency_overhead(config, concurrency)

security_score is an explicit, defended ordinal mapping (NOT hand-waved):
    classical = 0.0   -- no quantum resistance on either axis
    hybrid    = 0.8    -- ML-KEM-768 closes the HNDL/confidentiality threat
                          entirely (the axis with the long, currently-accruing
                          exposure window); ECDSA signing remains classically
                          vulnerable, but signatures only protect real-time
                          integrity, not the confidentiality of already-
                          harvested traffic, so this is a materially smaller
                          residual risk than full classical exposure
    full_pqc  = 1.0    -- quantum-resistant on both confidentiality and
                          integrity/authenticity axes

normalized_latency_overhead(config, concurrency) =
    (median_rtt_ms[config, concurrency] - median_rtt_ms[control, concurrency])
    / median_rtt_ms[control, concurrency]

Reported at three weightings (security-priority, performance-priority,
balanced) rather than a single arbitrary weighting, per the design doc's
explicit recommendation -- this is more defensible to reviewers than one
hard-coded number and lets a reader apply their own organizational risk
tolerance.

Usage:
    python -m analysis.tradeoff_matrix --raw-dir results/raw --output results/tradeoff_matrix.csv
"""

from __future__ import annotations

import argparse
import os

import pandas as pd

from analysis.aggregate import discard_warmup, load_raw

SECURITY_SCORES = {
    "control": None,   # excluded from the matrix -- it is the zero-overhead reference, not a real option
    "classical": 0.0,
    "hybrid": 0.8,
    "full_pqc": 1.0,
}

WEIGHTINGS = {
    "security_priority": {"w_sec": 0.8, "w_perf": 0.2},
    "balanced": {"w_sec": 0.5, "w_perf": 0.5},
    "performance_priority": {"w_sec": 0.2, "w_perf": 0.8},
}


def build_matrix(df: pd.DataFrame) -> pd.DataFrame:
    ok = df[df["error"].isna() | (df["error"] == "")]
    median_rtt = ok.groupby(["config", "concurrency"])["rtt_ms"].median()

    rows = []
    for concurrency in sorted(ok["concurrency"].unique()):
        try:
            control_rtt = median_rtt[("control", concurrency)]
        except KeyError:
            continue
        for config in ["classical", "hybrid", "full_pqc"]:
            try:
                config_rtt = median_rtt[(config, concurrency)]
            except KeyError:
                continue
            overhead_pct = (config_rtt - control_rtt) / control_rtt if control_rtt > 0 else None
            sec_score = SECURITY_SCORES[config]
            for weighting_name, w in WEIGHTINGS.items():
                score = w["w_sec"] * sec_score - w["w_perf"] * (overhead_pct or 0.0)
                rows.append({
                    "config": config,
                    "concurrency": concurrency,
                    "weighting": weighting_name,
                    "w_sec": w["w_sec"],
                    "w_perf": w["w_perf"],
                    "security_score": sec_score,
                    "median_rtt_ms": config_rtt,
                    "control_median_rtt_ms": control_rtt,
                    "normalized_latency_overhead": overhead_pct,
                    "composite_score": score,
                })
    return pd.DataFrame(rows)


def main():
    parser = argparse.ArgumentParser(description="PQ-Shield weighted trade-off matrix builder")
    parser.add_argument("--raw-dir", default="results/raw")
    parser.add_argument("--warmup-fraction", type=float, default=0.05)
    parser.add_argument("--output", default="results/tradeoff_matrix.csv")
    args = parser.parse_args()

    df = load_raw(args.raw_dir)
    df = discard_warmup(df, args.warmup_fraction)

    matrix = build_matrix(df)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    matrix.to_csv(args.output, index=False)
    print(f"Wrote trade-off matrix ({len(matrix)} rows) to {args.output}")

    for weighting_name in WEIGHTINGS:
        sub = matrix[matrix["weighting"] == weighting_name]
        print(f"\n=== {weighting_name} (w_sec={WEIGHTINGS[weighting_name]['w_sec']}, "
              f"w_perf={WEIGHTINGS[weighting_name]['w_perf']}) ===")
        for concurrency in sorted(sub["concurrency"].unique()):
            cs = sub[sub["concurrency"] == concurrency].sort_values("composite_score", ascending=False)
            best = cs.iloc[0]
            print(f"  concurrency={concurrency}: best = {best['config']} "
                  f"(score={best['composite_score']:.3f}, overhead={best['normalized_latency_overhead']:.1%})")


if __name__ == "__main__":
    main()
