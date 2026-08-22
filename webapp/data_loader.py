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


def get_trimmed_and_summary(warmup_fraction: float = 0.05):
    df = load_raw_df()
    if df is None:
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
