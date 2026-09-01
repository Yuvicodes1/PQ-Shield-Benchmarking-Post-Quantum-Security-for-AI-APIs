"""Aggregates results/streaming/*.csv (bench/streaming_runner.py output) into
summary tables: signature-byte overhead and time-to-first-token by strategy,
configuration, and response length.

Usage:
    python -m analysis.streaming_analysis
    python -m analysis.streaming_analysis --streaming-dir results/streaming --output results/streaming_summary.csv
"""

from __future__ import annotations

import argparse
import glob
import os

import pandas as pd


def load_streaming_raw(streaming_dir: str) -> pd.DataFrame:
    paths = sorted(glob.glob(os.path.join(streaming_dir, "*.csv")))
    if not paths:
        raise SystemExit(f"No CSV files found under {streaming_dir}. Run bench.streaming_runner first.")
    frames = [pd.read_csv(p) for p in paths]
    return pd.concat(frames, ignore_index=True)


def summarize(df: pd.DataFrame) -> pd.DataFrame:
    ok = df[df["error"].isna() | (df["error"] == "")]
    rows = []
    for (config, strategy, max_tokens, chunk_size), group in ok.groupby(
        ["config", "strategy", "max_tokens", "chunk_size_tokens"]
    ):
        rows.append({
            "config": config,
            "strategy": strategy,
            "max_tokens": max_tokens,
            "chunk_size_tokens": chunk_size,
            "n_repetitions": len(group),
            "ttft_ms_mean": group["ttft_ms"].mean(),
            "ttft_ms_median": group["ttft_ms"].median(),
            "total_ms_mean": group["total_ms"].mean(),
            "n_chunks_mean": group["n_chunks"].mean(),
            "total_signature_bytes_mean": group["total_signature_bytes"].mean(),
            "total_signing_ms_mean": group["total_signing_ms"].mean(),
            "total_verify_ms_mean": group["total_verify_ms"].mean(),
            "all_stream_fully_verified": bool(group["stream_fully_verified"].astype(bool).all()),
        })
    return pd.DataFrame(rows).sort_values(["config", "max_tokens", "chunk_size_tokens", "strategy"])


def strategy_comparison_at(df: pd.DataFrame, config: str, max_tokens: int, chunk_size_tokens: int) -> pd.DataFrame:
    """The specific side-by-side comparison the paper's headline table needs:
    for one (config, response length, chunk size), how do the three
    strategies compare on TTFT and signature bytes?"""
    summary = summarize(df)
    sub = summary[
        (summary["config"] == config)
        & (summary["max_tokens"] == max_tokens)
        & (summary["chunk_size_tokens"] == chunk_size_tokens)
    ]
    if sub.empty:
        return sub
    baseline_ttft = sub[sub["strategy"] == "buffer_and_sign"]["ttft_ms_mean"]
    baseline_ttft = baseline_ttft.iloc[0] if len(baseline_ttft) else None
    sub = sub.copy()
    if baseline_ttft:
        sub["ttft_speedup_vs_buffer_and_sign"] = baseline_ttft / sub["ttft_ms_mean"]
    per_chunk_bytes = sub[sub["strategy"] == "per_chunk"]["total_signature_bytes_mean"]
    per_chunk_bytes = per_chunk_bytes.iloc[0] if len(per_chunk_bytes) else None
    if per_chunk_bytes:
        sub["signature_bytes_reduction_vs_per_chunk"] = 1 - (sub["total_signature_bytes_mean"] / per_chunk_bytes)
    return sub[[
        "strategy", "ttft_ms_mean", "ttft_speedup_vs_buffer_and_sign",
        "total_signature_bytes_mean", "signature_bytes_reduction_vs_per_chunk",
        "all_stream_fully_verified",
    ]]


def main():
    parser = argparse.ArgumentParser(description="PQ-Shield streaming benchmark analysis")
    parser.add_argument("--streaming-dir", default="results/streaming")
    parser.add_argument("--output", default="results/streaming_summary.csv")
    parser.add_argument("--highlight-config", default="full_pqc")
    parser.add_argument("--highlight-max-tokens", type=int, default=None)
    parser.add_argument("--highlight-chunk-size", type=int, default=1)
    args = parser.parse_args()

    df = load_streaming_raw(args.streaming_dir)
    print(f"Loaded {len(df)} raw rows from {args.streaming_dir}")

    n_errors = (df["error"].notna() & (df["error"] != "")).sum()
    print(f"{n_errors} rows have a non-empty error and are excluded from statistics")

    summary = summarize(df)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    summary.to_csv(args.output, index=False)
    print(f"Wrote summary ({len(summary)} rows) to {args.output}")

    highlight_tokens = args.highlight_max_tokens or int(df["max_tokens"].max())
    print(f"\n=== Strategy comparison: config={args.highlight_config}, "
          f"max_tokens={highlight_tokens}, chunk_size_tokens={args.highlight_chunk_size} ===")
    comparison = strategy_comparison_at(df, args.highlight_config, highlight_tokens, args.highlight_chunk_size)
    if comparison.empty:
        print("(no matching rows -- check --highlight-* arguments against your sweep parameters)")
    else:
        print(comparison.to_string(index=False))


if __name__ == "__main__":
    main()
