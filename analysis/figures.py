"""Generates the minimum figure set called for in the design doc's Phase 6:

  1. RTT vs. concurrency, one line per config (log-x)              -> RQ1
  2. Bar chart: handshake/sign/verify decomposed per config         -> "where overhead comes from"
  3. Bytes-per-request stacked bar (key + ciphertext + signature)   -> RQ3 (raw byte side)
  4. HNDL storage-volume-per-1000-requests bar                      -> RQ3 (storage growth)
  4b. Streaming HNDL exposure vs. response length, by config         -> RQ3 (streaming scaling)
  5. MITM verify_ms comparison, tampered vs. untampered             -> RQ4
  6. Trade-off matrix heatmap (config x concurrency), one per weighting -> Layer 6 headline
  7. CPU% / RSS overhead bar (from bench.orchestrator resource sampling, if available)

Each figure function degrades gracefully (prints a note and skips) if its
required input file is not present, so this script can be run at any point
during the project rather than only once every experiment is complete.

Usage:
    python -m analysis.figures --results-dir results --output-dir outputs
"""

from __future__ import annotations

import argparse
import glob
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from analysis.aggregate import discard_warmup, load_raw

CONFIG_ORDER = ["control", "classical", "hybrid", "full_pqc"]
CONFIG_LABELS = {
    "control": "Control (unprotected)",
    "classical": "A: Classical\n(RSA-2048 + ECDSA)",
    "hybrid": "B: Hybrid\n(ML-KEM-768 + ECDSA)",
    "full_pqc": "C: Full PQC\n(ML-KEM-768 + ML-DSA-65)",
}
CONFIG_COLORS = {
    "control": "#888888",
    "classical": "#c0392b",
    "hybrid": "#e67e22",
    "full_pqc": "#2471a3",
}


def _save(fig, output_dir: str, name: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"{name}.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {path}")


def fig_rtt_vs_concurrency(df: pd.DataFrame, output_dir: str) -> None:
    ok = df[df["error"].isna() | (df["error"] == "")]
    fig, ax = plt.subplots(figsize=(7, 5))
    for config in CONFIG_ORDER:
        sub = ok[ok["config"] == config]
        if sub.empty:
            continue
        grouped = sub.groupby("concurrency")["rtt_ms"]
        x = sorted(grouped.groups.keys())
        median = [grouped.get_group(c).median() for c in x]
        p95 = [grouped.get_group(c).quantile(0.95) for c in x]
        ax.plot(x, median, marker="o", label=f"{config} (median)", color=CONFIG_COLORS[config])
        ax.plot(x, p95, marker="x", linestyle="--", alpha=0.6, color=CONFIG_COLORS[config],
                label=f"{config} (p95)")
    ax.set_xscale("log")
    ax.set_xlabel("Concurrency (log scale)")
    ax.set_ylabel("Round-trip time (ms)")
    ax.set_title("RTT vs. Concurrency by Configuration (RQ1)")
    ax.legend(fontsize=7, ncol=2)
    ax.grid(True, alpha=0.3)
    _save(fig, output_dir, "fig1_rtt_vs_concurrency")


def fig_overhead_decomposition(df: pd.DataFrame, output_dir: str, concurrency: int | None = None) -> None:
    ok = df[df["error"].isna() | (df["error"] == "")]
    if concurrency is None:
        concurrency = sorted(ok["concurrency"].unique())[len(ok["concurrency"].unique()) // 2]
    sub = ok[ok["concurrency"] == concurrency]

    metrics = ["handshake_ms", "server_decapsulate_ms", "server_sign_ms", "verify_ms"]
    metric_labels = ["Handshake RTT", "Server decapsulate", "Server sign", "Client verify"]
    configs = [c for c in CONFIG_ORDER if c != "control" and c in sub["config"].unique()]

    fig, ax = plt.subplots(figsize=(7, 5))
    x = np.arange(len(configs))
    width = 0.2
    for i, (metric, label) in enumerate(zip(metrics, metric_labels)):
        if metric not in sub.columns:
            continue
        vals = [sub[sub["config"] == c][metric].median() for c in configs]
        ax.bar(x + i * width, vals, width, label=label)
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels([CONFIG_LABELS[c] for c in configs], fontsize=8)
    ax.set_ylabel("Median time (ms)")
    ax.set_title(f"Where Overhead Comes From (concurrency={concurrency})")
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3, axis="y")
    _save(fig, output_dir, "fig2_overhead_decomposition")


def fig_bytes_per_request(df: pd.DataFrame, output_dir: str) -> None:
    ok = df[df["error"].isna() | (df["error"] == "")]
    configs = [c for c in CONFIG_ORDER if c != "control" and c in ok["config"].unique()]
    if not configs:
        print("No protected-config rows with byte data -- skipping fig3")
        return

    kex_bytes, sig_bytes = [], []
    for c in configs:
        sub = ok[ok["config"] == c]
        kex_bytes.append(sub["kex_blob_bytes"].dropna().median() if "kex_blob_bytes" in sub else 0)
        sig_bytes.append(sub["signature_bytes"].dropna().median() if "signature_bytes" in sub else 0)

    fig, ax = plt.subplots(figsize=(6, 5))
    x = np.arange(len(configs))
    ax.bar(x, kex_bytes, label="Key-establishment blob", color="#2471a3")
    ax.bar(x, sig_bytes, bottom=kex_bytes, label="Signature", color="#e67e22")
    ax.set_xticks(x)
    ax.set_xticklabels([CONFIG_LABELS[c] for c in configs], fontsize=8)
    ax.set_ylabel("Bytes per request")
    ax.set_title("Wire Bytes per Request by Configuration (RQ3)")
    ax.legend()
    ax.grid(True, alpha=0.3, axis="y")
    _save(fig, output_dir, "fig3_bytes_per_request")


def fig_hndl_storage(results_dir: str, output_dir: str) -> None:
    summary_paths = sorted(glob.glob(os.path.join(results_dir, "hndl", "*-summary.json")))
    if not summary_paths:
        print("No HNDL summary JSONs found -- skipping fig4 (run threats.hndl_capture first)")
        return
    summaries = [json.load(open(p)) for p in summary_paths]
    configs = [s["config"] for s in summaries]
    projected = [s.get("projected_bytes_per_1000_requests") or 0 for s in summaries]
    decryptable = [s.get("kex_decryptable_under_future_crqc") for s in summaries]

    fig, ax = plt.subplots(figsize=(6, 5))
    colors = ["#c0392b" if d else "#2471a3" for d in decryptable]
    ax.bar(configs, projected, color=colors)
    ax.set_ylabel("Projected bytes stored per 1,000 requests")
    ax.set_title("HNDL Storage Growth by Configuration (RQ3)")
    ax.grid(True, alpha=0.3, axis="y")
    handles = [
        plt.Rectangle((0, 0), 1, 1, color="#c0392b", label="Key-exchange ciphertext decryptable under future CRQC"),
        plt.Rectangle((0, 0), 1, 1, color="#2471a3", label="Not decryptable under future CRQC (lattice-based)"),
    ]
    ax.legend(handles=handles, fontsize=7, loc="upper left")
    _save(fig, output_dir, "fig4_hndl_storage")


def fig_streaming_hndl_exposure(results_dir: str, output_dir: str) -> None:
    """Streaming counterpart to fig_hndl_storage: exposure vs. response
    length, one line per config, from threats.streaming_hndl_experiment's
    per-config *-streaming-hndl-summary.json files. Same red/blue
    decryptable-under-future-CRQC color convention as fig4 -- this is the
    same H3 finding as fig4, just made length-dependent, not a new one.

    Plots `decryptable_bytes_under_future_crqc_by_length`, not raw
    `total_bytes_harvestable_by_length` -- classical's decryptable bytes
    equal its harvestable bytes (100% exposed) and grow with length;
    hybrid/full_pqc's decryptable bytes are flat at zero regardless of how
    many bytes were actually harvested, which is the point being made."""
    summary_paths = sorted(glob.glob(os.path.join(results_dir, "hndl", "streaming", "*-streaming-hndl-summary.json")))
    if not summary_paths:
        print("No streaming-HNDL summary JSONs found -- skipping fig4b "
              "(run threats.streaming_hndl_experiment first)")
        return
    summaries = [json.load(open(p)) for p in summary_paths]

    fig, ax = plt.subplots(figsize=(7, 5))
    for s in summaries:
        config = s["config"]
        color = "#c0392b" if s.get("kex_decryptable_under_future_crqc") else "#2471a3"
        ax.plot(
            s["max_tokens_values"], s["decryptable_bytes_under_future_crqc_by_length"],
            marker="o", color=color, label=CONFIG_LABELS.get(config, config).replace("\n", " "),
        )
    ax.set_xlabel("Response length (max_tokens)")
    ax.set_ylabel("Bytes decryptable under a future CRQC")
    ax.set_title("Streaming HNDL Exposure vs. Response Length")
    ax.grid(True, alpha=0.3)
    handles = [
        plt.Line2D([0], [0], color="#c0392b", marker="o", label="Decryptable (RSA/ECDH key establishment)"),
        plt.Line2D([0], [0], color="#2471a3", marker="o", label="Not decryptable (ML-KEM-768 key establishment)"),
    ]
    ax.legend(handles=handles, fontsize=7, loc="upper left")
    _save(fig, output_dir, "fig4b_streaming_hndl_exposure")


def fig_mitm_detection(results_dir: str, output_dir: str) -> None:
    summary_paths = sorted(glob.glob(os.path.join(results_dir, "mitm", "*-summary.json")))
    if not summary_paths:
        print("No MITM summary JSONs found -- skipping fig5 (run threats.mitm_experiment first)")
        return
    summaries = [json.load(open(p)) for p in summary_paths]
    labels = [f"{s['config']}\n({s['tamper_target']})" for s in summaries]
    rates = [s.get("detection_rate") or 0 for s in summaries]
    det_ms = [s.get("detection_ms_mean") or 0 for s in summaries]

    fig, axes = plt.subplots(1, 2, figsize=(11, 5))
    axes[0].bar(labels, [r * 100 for r in rates], color="#2471a3")
    axes[0].set_ylabel("Detection rate (%)")
    axes[0].set_title("Tamper Detection Rate (RQ4)")
    axes[0].set_ylim(0, 105)
    axes[0].grid(True, alpha=0.3, axis="y")

    axes[1].bar(labels, det_ms, color="#e67e22")
    axes[1].set_ylabel("Mean detection latency (ms)")
    axes[1].set_title("Tamper Detection Latency (RQ4)")
    axes[1].grid(True, alpha=0.3, axis="y")

    for ax in axes:
        ax.tick_params(axis="x", labelsize=7)

    _save(fig, output_dir, "fig5_mitm_detection")


def fig_tradeoff_heatmap(results_dir: str, output_dir: str) -> None:
    path = os.path.join(results_dir, "tradeoff_matrix.csv")
    if not os.path.isfile(path):
        print("No tradeoff_matrix.csv found -- skipping fig6 (run analysis.tradeoff_matrix first)")
        return
    df = pd.read_csv(path)
    weightings = df["weighting"].unique()

    fig, axes = plt.subplots(1, len(weightings), figsize=(5 * len(weightings), 4.5))
    if len(weightings) == 1:
        axes = [axes]

    for ax, weighting in zip(axes, weightings):
        sub = df[df["weighting"] == weighting]
        pivot = sub.pivot(index="config", columns="concurrency", values="composite_score")
        pivot = pivot.reindex([c for c in ["classical", "hybrid", "full_pqc"] if c in pivot.index])
        im = ax.imshow(pivot.values, cmap="RdYlGn", aspect="auto")
        ax.set_xticks(range(len(pivot.columns)))
        ax.set_xticklabels(pivot.columns)
        ax.set_yticks(range(len(pivot.index)))
        ax.set_yticklabels(pivot.index)
        ax.set_title(weighting.replace("_", " ").title())
        for i in range(pivot.shape[0]):
            for j in range(pivot.shape[1]):
                val = pivot.values[i, j]
                if not np.isnan(val):
                    ax.text(j, i, f"{val:.2f}", ha="center", va="center", fontsize=9)
        fig.colorbar(im, ax=ax, shrink=0.7)
    fig.suptitle("Security-Performance Trade-off Matrix (Layer 6)")
    _save(fig, output_dir, "fig6_tradeoff_heatmap")


def fig_resource_overhead(results_dir: str, output_dir: str) -> None:
    """CPU%/RSS are captured per-server-process by bench.orchestrator only
    if invoked with resource sampling attached; when not available (the
    default matrix run doesn't attach a sampler because the orchestrator
    manages server subprocesses itself), this figure notes the gap rather
    than fabricating data."""
    print("fig7 (CPU/RSS heatmap) requires per-cell resource sampling; "
          "see bench/runner.py --server-pid for standalone cells with sampling enabled. Skipping.")


def main():
    parser = argparse.ArgumentParser(description="PQ-Shield figure generator")
    parser.add_argument("--results-dir", default="results")
    parser.add_argument("--output-dir", default="outputs")
    parser.add_argument("--warmup-fraction", type=float, default=0.05)
    args = parser.parse_args()

    raw_dir = os.path.join(args.results_dir, "raw")
    df = load_raw(raw_dir)
    df = discard_warmup(df, args.warmup_fraction)

    fig_rtt_vs_concurrency(df, args.output_dir)
    fig_overhead_decomposition(df, args.output_dir)
    fig_bytes_per_request(df, args.output_dir)
    fig_hndl_storage(args.results_dir, args.output_dir)
    fig_streaming_hndl_exposure(args.results_dir, args.output_dir)
    fig_mitm_detection(args.results_dir, args.output_dir)
    fig_tradeoff_heatmap(args.results_dir, args.output_dir)
    fig_resource_overhead(args.results_dir, args.output_dir)


if __name__ == "__main__":
    main()
