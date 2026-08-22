"""Generates the aggregate 'smoke-test' comparison chart referenced in the
project README: mean +/- standard deviation error bars for protected-request
RTT, handshake time, and reported server crypto+inference time, across
whichever raw CSVs are present. Unlike analysis/figures.py (the full paper
figure set, which expects the complete matrix), this is meant to be run at
any point during development to sanity-check partial results.

Usage:
    python -m analysis.plot_metrics
    python -m analysis.plot_metrics --input results/raw/classical-c10-r1.csv results/raw/full-pqc-c10-r1.csv --output outputs/c10-comparison.png
"""

from __future__ import annotations

import argparse
import glob
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

CONFIG_ORDER = ["control", "classical", "hybrid", "full_pqc"]
CONFIG_COLORS = {"control": "#888888", "classical": "#c0392b", "hybrid": "#e67e22", "full_pqc": "#2471a3"}


def main():
    parser = argparse.ArgumentParser(description="PQ-Shield quick metrics comparison plot")
    parser.add_argument("--input", nargs="*", default=None, help="Specific CSV files; default = all of results/raw/*.csv")
    parser.add_argument("--output", default="outputs/benchmark-comparison.png")
    args = parser.parse_args()

    paths = args.input or sorted(glob.glob("results/raw/*.csv"))
    if not paths:
        raise SystemExit("No CSV files found. Run bench.orchestrator or bench.runner first.")

    df = pd.concat([pd.read_csv(p) for p in paths], ignore_index=True)
    ok = df[df["error"].isna() | (df["error"] == "")]

    metrics = [
        ("rtt_ms", "RTT (ms)"),
        ("handshake_ms", "Handshake time (ms)"),
        ("server_total_ms", "Server crypto + inference time (ms)"),
    ]
    configs = [c for c in CONFIG_ORDER if c in ok["config"].unique()]

    fig, axes = plt.subplots(1, len(metrics), figsize=(5 * len(metrics), 4.5))
    if len(metrics) == 1:
        axes = [axes]

    for ax, (metric, label) in zip(axes, metrics):
        if metric not in ok.columns:
            continue
        means, stds = [], []
        for c in configs:
            vals = ok[ok["config"] == c][metric].dropna().values
            means.append(np.mean(vals) if len(vals) else 0)
            stds.append(np.std(vals) if len(vals) else 0)
        x = np.arange(len(configs))
        colors = [CONFIG_COLORS[c] for c in configs]
        ax.bar(x, means, yerr=stds, capsize=4, color=colors)
        ax.set_xticks(x)
        ax.set_xticklabels(configs, rotation=20, fontsize=8)
        ax.set_ylabel(label)
        ax.set_title(label)
        ax.grid(True, alpha=0.3, axis="y")

    fig.suptitle(f"PQ-Shield benchmark comparison ({len(paths)} CSV file(s), {len(ok)} valid requests)")
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    fig.savefig(args.output, dpi=150, bbox_inches="tight")
    print(f"Wrote {args.output}")
    print("NOTE: treat this as a smoke-test visualization -- overlapping error bars mean small")
    print("differences are not yet statistically meaningful. See analysis/aggregate.py for the")
    print("Mann-Whitney U significance tests used in the paper.")


if __name__ == "__main__":
    main()
