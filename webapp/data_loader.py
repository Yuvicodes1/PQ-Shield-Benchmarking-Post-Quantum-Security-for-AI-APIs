"""Loads results/raw/*.csv and results/{hndl,mitm}/*-summary.json for the
Results Dashboard and Threat Scenarios pages, and wraps analysis/aggregate.py
and analysis/tradeoff_matrix.py's exact computation logic so the dashboard's
numbers are always identical to what `python -m analysis.aggregate` /
`analysis.tradeoff_matrix` would print on the command line -- no
duplicated/divergent math.
"""

from __future__ import annotations

import glob
import json
import os

import pandas as pd

from analysis.aggregate import discard_warmup, mann_whitney_vs_control, summarize
from analysis.tradeoff_matrix import SECURITY_SCORES

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(REPO_ROOT, "results", "raw")
HNDL_DIR = os.path.join(REPO_ROOT, "results", "hndl")
MITM_DIR = os.path.join(REPO_ROOT, "results", "mitm")
SWEEP_SUMMARY_DIR = os.path.join(REPO_ROOT, "results", "sweep_summaries")
STREAMING_DIR = os.path.join(REPO_ROOT, "results", "streaming")
STREAMING_MITM_DIR = os.path.join(REPO_ROOT, "results", "streaming", "mitm")

CONFIG_ORDER = ["control", "classical", "hybrid", "full_pqc"]
CONFIG_LABELS = {
    "control": "Control",
    "classical": "A: Classical",
    "hybrid": "B: Hybrid",
    "full_pqc": "C: Full PQC",
}


def load_raw_df() -> pd.DataFrame | None:
    paths = sorted(glob.glob(os.path.join(RAW_DIR, "*.csv")))
    if not paths:
        return None
    frames = []
    for p in paths:
        try:
            frames.append(pd.read_csv(p))
        except Exception:
            continue
    if not frames:
        return None
    return pd.concat(frames, ignore_index=True)


def raw_file_inventory() -> pd.DataFrame:
    """One row per raw CSV file, for a 'what data do I have' table."""
    paths = sorted(glob.glob(os.path.join(RAW_DIR, "*.csv")))
    rows = []
    for p in paths:
        try:
            df = pd.read_csv(p)
            n_errors = (df["error"].notna() & (df["error"] != "")).sum()
            rows.append({
                "file": os.path.basename(p),
                "config": df["config"].iloc[0] if len(df) else None,
                "concurrency": int(df["concurrency"].iloc[0]) if len(df) else None,
                "repetition": int(df["repetition"].iloc[0]) if len(df) else None,
                "n_requests": len(df),
                "n_errors": int(n_errors),
                "error_rate": n_errors / len(df) if len(df) else None,
            })
        except Exception as exc:
            rows.append({"file": os.path.basename(p), "config": None, "concurrency": None,
                         "repetition": None, "n_requests": None, "n_errors": None, "error_rate": None})
    return pd.DataFrame(rows)


def streaming_file_inventory() -> pd.DataFrame:
    """One row per results/streaming/*.csv file (bench.streaming_runner's
    per-config output), for the Benchmark Runner page's streaming tab --
    mirrors raw_file_inventory()'s role for the concurrency sweep."""
    paths = sorted(glob.glob(os.path.join(STREAMING_DIR, "*.csv")))
    rows = []
    for p in paths:
        try:
            df = pd.read_csv(p)
            n_errors = (df["error"].notna() & (df["error"] != "")).sum() if "error" in df.columns else 0
            rows.append({
                "file": os.path.basename(p),
                "config": df["config"].iloc[0] if len(df) else None,
                "n_transactions": len(df),
                "n_errors": int(n_errors),
                "strategies": ", ".join(sorted(df["strategy"].dropna().unique())) if len(df) else None,
                "mean_ttft_ms": round(df["ttft_ms"].mean(), 1) if "ttft_ms" in df.columns and len(df) else None,
            })
        except Exception:
            rows.append({"file": os.path.basename(p), "config": None, "n_transactions": None,
                         "n_errors": None, "strategies": None, "mean_ttft_ms": None})
    return pd.DataFrame(rows)


def load_streaming_df() -> pd.DataFrame | None:
    """Concatenates every results/streaming/*.csv into one frame, for the
    Results Dashboard's streaming section. None if no streaming sweep has
    been run yet."""
    paths = sorted(glob.glob(os.path.join(STREAMING_DIR, "*.csv")))
    if not paths:
        return None
    frames = [pd.read_csv(p) for p in paths]
    return pd.concat(frames, ignore_index=True)


LEGACY_RUN_ID = "legacy"  # bucket for rows written before run_id existed


def _fill_legacy_run_id(df: pd.DataFrame) -> pd.DataFrame:
    """Rows from CSVs written before run_id was introduced have no run_id
    column at all; pd.concat gives those rows NaN rather than dropping them.
    Bucket them under one explicit label so they're still visible (under
    "All runs") instead of silently vanishing from every run-scoped view."""
    if "run_id" not in df.columns:
        df = df.copy()
        df["run_id"] = LEGACY_RUN_ID
    else:
        df = df.copy()
        df["run_id"] = df["run_id"].fillna(LEGACY_RUN_ID)
    return df


def list_runs(df: pd.DataFrame) -> list[str]:
    """Distinct run_ids present in df, most recent first. run_id is a
    time.strftime("%Y%m%dT%H%M%S") string, so lexicographic sort == chronological."""
    if df is None or df.empty or "run_id" not in df.columns:
        return []
    return sorted(df["run_id"].dropna().unique().tolist(), reverse=True)


def latest_run_id(df: pd.DataFrame) -> str | None:
    runs = [r for r in list_runs(df) if r != LEGACY_RUN_ID]
    if runs:
        return runs[0]
    all_runs = list_runs(df)
    return all_runs[0] if all_runs else None


def run_label(run_id: str, df: pd.DataFrame | None = None) -> str:
    """Human-readable label for a run_id, e.g. '2026-08-24 22:08:xx (12 rows)'."""
    if run_id == LEGACY_RUN_ID:
        base = "Legacy data (no run_id -- written before run tracking existed)"
    else:
        try:
            from datetime import datetime

            base = datetime.strptime(run_id, "%Y%m%dT%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            base = run_id
    if df is not None and "run_id" in df.columns:
        n = int((df["run_id"] == run_id).sum())
        base = f"{base} ({n:,} rows)"
    return base


def get_available_runs() -> tuple[list[str], str | None]:
    """(all run_ids most-recent-first, latest non-legacy run_id) for the
    Results Dashboard's run selector. Returns ([], None) if no raw data yet."""
    df = load_raw_df()
    if df is None:
        return [], None
    df = _fill_legacy_run_id(df)
    return list_runs(df), latest_run_id(df)


def get_trimmed_and_summary(warmup_fraction: float = 0.05, run_id: str | None = None):
    """run_id=None (default) uses ALL historical data, matching analysis.aggregate's
    CLI behavior. Pass a specific run_id, or the sentinel "__latest__", to scope
    to one sweep -- see the Results Dashboard's run selector."""
    df = load_raw_df()
    if df is None:
        return None, None
    df = _fill_legacy_run_id(df)
    if run_id == "__latest__":
        run_id = latest_run_id(df)
    if run_id is not None:
        df = df[df["run_id"] == run_id]
        if df.empty:
            return None, None
    trimmed = discard_warmup(df, warmup_fraction)
    return trimmed, summarize(trimmed)


def get_significance(trimmed_df: pd.DataFrame | None, metric: str = "rtt_ms") -> pd.DataFrame | None:
    if trimmed_df is None or trimmed_df.empty:
        return None
    return mann_whitney_vs_control(trimmed_df, metric=metric)


def build_custom_tradeoff(trimmed_df: pd.DataFrame, w_sec: float, w_perf: float) -> pd.DataFrame:
    """Same composite-score formula as analysis/tradeoff_matrix.py's
    build_matrix(), parameterized by a single user-chosen (w_sec, w_perf)
    pair for the dashboard's interactive weighting sliders."""
    ok = trimmed_df[trimmed_df["error"].isna() | (trimmed_df["error"] == "")]
    median_rtt = ok.groupby(["config", "concurrency"])["rtt_ms"].median()

    rows = []
    for concurrency in sorted(ok["concurrency"].unique()):
        if ("control", concurrency) not in median_rtt.index:
            continue
        control_rtt = median_rtt[("control", concurrency)]
        for config in ["classical", "hybrid", "full_pqc"]:
            if (config, concurrency) not in median_rtt.index:
                continue
            config_rtt = median_rtt[(config, concurrency)]
            overhead = (config_rtt - control_rtt) / control_rtt if control_rtt > 0 else 0.0
            sec_score = SECURITY_SCORES[config]
            score = w_sec * sec_score - w_perf * overhead
            rows.append({
                "config": config,
                "concurrency": int(concurrency),
                "security_score": sec_score,
                "median_rtt_ms": config_rtt,
                "control_median_rtt_ms": control_rtt,
                "normalized_latency_overhead": overhead,
                "composite_score": score,
            })
    return pd.DataFrame(rows)


def load_hndl_summaries() -> list[dict]:
    paths = sorted(glob.glob(os.path.join(HNDL_DIR, "*-summary.json")))
    out = []
    for p in paths:
        try:
            out.append(json.load(open(p)))
        except Exception:
            continue
    return out


def load_mitm_summaries() -> list[dict]:
    paths = sorted(glob.glob(os.path.join(MITM_DIR, "*-summary.json")))
    out = []
    for p in paths:
        try:
            out.append(json.load(open(p)))
        except Exception:
            continue
    return out


def load_streaming_mitm_summaries() -> list[dict]:
    """threats/streaming_mitm_experiment.py's per-(config, strategy, attack)
    summaries -- kept in their own directory/loader rather than folded into
    load_mitm_summaries() above, since the two have different shapes
    (tamper_target/detection_ms_mean vs. strategy/attack/
    fraction_delivered_before_detection_mean) and mixing them would produce
    a confusing combined table."""
    paths = sorted(glob.glob(os.path.join(STREAMING_MITM_DIR, "*-summary.json")))
    out = []
    for p in paths:
        try:
            out.append(json.load(open(p)))
        except Exception:
            continue
    return out


def load_sweep_summaries(run_id: str | None = None) -> pd.DataFrame:
    """Per-cell sweep summaries written by bench.orchestrator.run_full_sweep --
    throughput, error count, and server-process CPU%/RSS during that cell
    (crypto.instrumentation.ResourceSampler). One file per run_id under
    results/sweep_summaries/. Runs from before this existed have no file and
    are simply absent here -- not an error, just no resource data for them.
    """
    paths = sorted(glob.glob(os.path.join(SWEEP_SUMMARY_DIR, "*.json")))
    rows = []
    for p in paths:
        try:
            rows.extend(json.load(open(p)))
        except Exception:
            continue
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    if run_id is not None and "run_id" in df.columns:
        df = df[df["run_id"] == run_id]
    return df
