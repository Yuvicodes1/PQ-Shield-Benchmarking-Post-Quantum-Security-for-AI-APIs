"""Aggregates all raw per-request CSVs under results/raw/ into summary
statistics per (config, concurrency): mean, median, standard deviation,
p95, p99 -- per the design doc's statistical-rigor checklist, which calls
out that latency distributions are right-skewed and mean-only reporting is
misleading for an SLA-relevant claim.

Discards the first `--warmup-fraction` of requests in each raw CSV as
JIT/connection-pool warm-up before computing statistics (also per the
design doc), and reports a non-parametric Mann-Whitney U test comparing
each protected configuration's RTT distribution against the control
baseline at the same concurrency level.

Usage:
    python -m analysis.aggregate --raw-dir results/raw --output results/aggregate_stats.csv
"""

from __future__ import annotations

import argparse
import glob
import os

import numpy as np
import pandas as pd
from scipy import stats

METRIC_COLUMNS = [
    "rtt_ms", "handshake_ms", "total_ms",
    "server_decapsulate_ms", "server_inference_ms", "server_sign_ms",
    "server_crypto_ms", "server_total_ms", "verify_ms",
]


def load_raw(raw_dir: str) -> pd.DataFrame:
    paths = sorted(glob.glob(os.path.join(raw_dir, "*.csv")))
    if not paths:
        raise SystemExit(f"No CSV files found under {raw_dir}. Run bench.orchestrator first.")
    frames = [pd.read_csv(p) for p in paths]
    df = pd.concat(frames, ignore_index=True)
    return df


def discard_warmup(df: pd.DataFrame, warmup_fraction: float) -> pd.DataFrame:
    """Drops the first `warmup_fraction` of rows (by request_index) within
    each (config, concurrency, repetition) group.

    Implemented via an explicit boolean mask rather than groupby().apply()
    because groupby(...).apply(...) with group_keys=False silently drops
    the grouping columns from the result on some pandas versions when the
    applied function returns a frame with the same non-key columns as the
    input -- a boolean mask sidesteps that entirely and is easier to audit.
    """
    df = df.sort_values(["config", "concurrency", "repetition", "request_index"]).reset_index(drop=True)
    keep_mask = pd.Series(True, index=df.index)

    for (_config, _concurrency, _repetition), group in df.groupby(
        ["config", "concurrency", "repetition"], sort=False
    ):
        n = len(group)
        if n < 20:
            continue  # too few rows to safely discard any as warm-up
        cutoff = int(n * warmup_fraction)
        drop_idx = group.index[:cutoff]
        keep_mask.loc[drop_idx] = False

    return df[keep_mask].reset_index(drop=True)


def summarize(df: pd.DataFrame) -> pd.DataFrame:
    ok = df[df["error"].isna() | (df["error"] == "")]
    rows = []
    for (config, concurrency), group in ok.groupby(["config", "concurrency"]):
        row = {
            "config": config,
            "concurrency": concurrency,
            "n_requests": len(group),
            "n_repetitions": group["repetition"].nunique(),
        }
        for col in METRIC_COLUMNS:
            if col not in group.columns:
                continue
            vals = group[col].dropna().values
            if len(vals) == 0:
                continue
            row[f"{col}_mean"] = float(np.mean(vals))
            row[f"{col}_median"] = float(np.median(vals))
            row[f"{col}_std"] = float(np.std(vals, ddof=1)) if len(vals) > 1 else 0.0
            row[f"{col}_p95"] = float(np.percentile(vals, 95))
            row[f"{col}_p99"] = float(np.percentile(vals, 99))
        rows.append(row)
    return pd.DataFrame(rows).sort_values(["concurrency", "config"])


def mann_whitney_vs_control(df: pd.DataFrame, metric: str = "rtt_ms") -> pd.DataFrame:
    """Non-parametric test: is each protected config's RTT distribution
    significantly different from control, at the same concurrency level?"""
    ok = df[df["error"].isna() | (df["error"] == "")]
    rows = []
    for concurrency, group in ok.groupby("concurrency"):
        control_vals = group[group["config"] == "control"][metric].dropna().values
        if len(control_vals) < 2:
            continue
        for config in group["config"].unique():
            if config == "control":
                continue
            treatment_vals = group[group["config"] == config][metric].dropna().values
            if len(treatment_vals) < 2:
                continue
            u_stat, p_value = stats.mannwhitneyu(treatment_vals, control_vals, alternative="two-sided")
            rows.append({
                "concurrency": concurrency,
                "config": config,
                "metric": metric,
                "n_control": len(control_vals),
                "n_treatment": len(treatment_vals),
                "median_control": float(np.median(control_vals)),
                "median_treatment": float(np.median(treatment_vals)),
                "overhead_pct_vs_control": float(
                    (np.median(treatment_vals) - np.median(control_vals)) / np.median(control_vals) * 100
                ) if np.median(control_vals) > 0 else None,
                "u_statistic": float(u_stat),
                "p_value": float(p_value),
                "significant_at_0.05": bool(p_value < 0.05),
            })
    if not rows:
        return pd.DataFrame(columns=[
            "concurrency", "config", "metric", "n_control", "n_treatment",
            "median_control", "median_treatment", "overhead_pct_vs_control",
            "u_statistic", "p_value", "significant_at_0.05",
        ])
    return pd.DataFrame(rows).sort_values(["concurrency", "config"])


def main():
    parser = argparse.ArgumentParser(description="PQ-Shield raw CSV aggregator")
    parser.add_argument("--raw-dir", default="results/raw")
    parser.add_argument("--warmup-fraction", type=float, default=0.05)
    parser.add_argument("--output", default="results/aggregate_stats.csv")
    parser.add_argument("--significance-output", default="results/significance_vs_control.csv")
    args = parser.parse_args()

    df = load_raw(args.raw_dir)
    print(f"Loaded {len(df)} raw rows from {args.raw_dir}")

    df_trimmed = discard_warmup(df, args.warmup_fraction)
    print(f"{len(df_trimmed)} rows after discarding {args.warmup_fraction:.0%} warm-up per cell")

    n_errors = df_trimmed["error"].notna().sum() - (df_trimmed["error"] == "").sum()
    print(f"{n_errors} rows have a non-empty error and are excluded from statistics")

    summary = summarize(df_trimmed)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    summary.to_csv(args.output, index=False)
    print(f"Wrote summary statistics ({len(summary)} rows) to {args.output}")

    sig = mann_whitney_vs_control(df_trimmed, metric="rtt_ms")
    sig.to_csv(args.significance_output, index=False)
    print(f"Wrote Mann-Whitney U significance tests ({len(sig)} rows) to {args.significance_output}")


if __name__ == "__main__":
    main()
