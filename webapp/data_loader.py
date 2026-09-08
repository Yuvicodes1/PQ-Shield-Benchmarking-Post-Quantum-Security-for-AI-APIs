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
from analysis.tradeoff_matrix import build_matrix_at

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(REPO_ROOT, "results", "raw")
HNDL_DIR = os.path.join(REPO_ROOT, "results", "hndl")
MITM_DIR = os.path.join(REPO_ROOT, "results", "mitm")
SWEEP_SUMMARY_DIR = os.path.join(REPO_ROOT, "results", "sweep_summaries")
STREAMING_DIR = os.path.join(REPO_ROOT, "results", "streaming")
STREAMING_MITM_DIR = os.path.join(REPO_ROOT, "results", "streaming", "mitm")
STREAMING_HNDL_DIR = os.path.join(REPO_ROOT, "results", "hndl", "streaming")

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
    per-config, per-sweep output -- one file per config per run_id since
    bench.streaming_runner.run_sweep started tagging output with a run_id;
    older files predating that have no run_id column at all), for the
    Benchmark Runner page's streaming tab -- mirrors raw_file_inventory()'s
    role for the concurrency sweep."""
    paths = sorted(glob.glob(os.path.join(STREAMING_DIR, "*.csv")))
    rows = []
    for p in paths:
        try:
            df = pd.read_csv(p)
            n_errors = (df["error"].notna() & (df["error"] != "")).sum() if "error" in df.columns else 0
            rows.append({
                "file": os.path.basename(p),
                "run_id": df["run_id"].iloc[0] if "run_id" in df.columns and len(df) else LEGACY_RUN_ID,
                "config": df["config"].iloc[0] if len(df) else None,
                "n_transactions": len(df),
                "n_errors": int(n_errors),
                "strategies": ", ".join(sorted(df["strategy"].dropna().unique())) if len(df) else None,
                "mean_ttft_ms": round(df["ttft_ms"].mean(), 1) if "ttft_ms" in df.columns and len(df) else None,
            })
        except Exception:
            rows.append({"file": os.path.basename(p), "run_id": None, "config": None, "n_transactions": None,
                         "n_errors": None, "strategies": None, "mean_ttft_ms": None})
    return pd.DataFrame(rows)


def load_streaming_df(run_id: str | None = None) -> pd.DataFrame | None:
    """Concatenates every results/streaming/*.csv into one frame, for the
    Results Dashboard's streaming section. None if no streaming sweep has
    been run yet.

    run_id=None (default) returns everything ever collected, across every
    sweep -- matching this function's original behavior, and load_raw_df's
    for the concurrency sweep. Pass a specific run_id, or the sentinel
    "__latest__", to scope to just one streaming sweep -- see
    get_available_streaming_runs(). Files written before
    bench.streaming_runner started tagging output with a run_id have no
    run_id column at all; those rows are bucketed under LEGACY_RUN_ID
    rather than silently dropped, same as _fill_legacy_run_id does for the
    concurrency sweep's raw data.
    """
    paths = sorted(glob.glob(os.path.join(STREAMING_DIR, "*.csv")))
    if not paths:
        return None
    frames = [pd.read_csv(p) for p in paths]
    df = pd.concat(frames, ignore_index=True)
    df = _fill_legacy_run_id(df)
    if run_id == "__latest__":
        run_id = latest_run_id(df)
    if run_id is not None:
        df = df[df["run_id"] == run_id]
        if df.empty:
            return None
    return df


def get_available_streaming_runs() -> tuple[list[str], str | None]:
    """(all streaming run_ids most-recent-first, latest non-legacy run_id)
    for the Results Dashboard streaming section's run selector -- mirrors
    get_available_runs() for the concurrency sweep. Returns ([], None) if
    no streaming sweep has been run yet."""
    df = load_streaming_df()
    if df is None:
        return [], None
    return list_runs(df), latest_run_id(df)


def get_unified_runs() -> tuple[list[dict], tuple[str, str | None] | None]:
    """One merged, chronologically-sorted list of every run the Results
    Dashboard can show -- concurrency-sweep runs (results/raw/) and
    streaming-sweep runs (results/streaming/) interleaved, not grouped by
    type. Both experiment types share the same run_id generator
    (bench.runner.new_run_id -> time.strftime("%Y%m%dT%H%M%S")), so a plain
    lexicographic sort on run_id is already chronological across both.

    Each entry is a dict: {"key": (type, run_id_or_None), "type": "concurrency"
    | "streaming", "run_id": str | None, "label": str}. run_id=None marks one
    of the two "all runs combined" pseudo-entries (one per type, since the
    two schemas -- RTT vs. time-to-first-token -- can't be combined into one
    meaningful aggregate). "key" is what a caller should pass as the widget's
    option value; it's a (type, run_id) tuple rather than a bare run_id so the
    two experiment types' independent "legacy" buckets (and, in the
    astronomically unlikely case two sweeps started in the same second, their
    real run_ids) never collide.

    Returns (entries, default_key) -- default_key points at the single most
    recent non-legacy run across both types, matching each individual
    selector's previous "most recent" default; entries=[] / default_key=None
    if neither results/raw/ nor results/streaming/ has any data yet.
    """
    conc_runs, _ = get_available_runs()
    stream_runs, _ = get_available_streaming_runs()

    def _type_label(t: str) -> str:
        return "Concurrency Sweep" if t == "concurrency" else "Streaming Sweep"

    def _timed_label(run_id: str, t: str) -> str:
        if run_id == LEGACY_RUN_ID:
            base = "Legacy data (no run_id)"
        else:
            try:
                from datetime import datetime

                base = datetime.strptime(run_id, "%Y%m%dT%H%M%S").strftime("%Y-%m-%d %H:%M")
            except ValueError:
                base = run_id
        return f"{base} — {_type_label(t)}"

    _all_label = {"concurrency": "All concurrency-sweep runs combined", "streaming": "All streaming runs combined"}

    entries: list[dict] = []
    # Both "all combined" pseudo-entries up front, mirroring the previous
    # single selector's "All runs combined" always sorting first.
    for t, runs in (("concurrency", conc_runs), ("streaming", stream_runs)):
        if runs:
            entries.append({
                "key": (t, None), "type": t, "run_id": None,
                "label": f"{_all_label[t]} ({len(runs)} runs)",
            })

    timed: list[dict] = []
    for t, runs in (("concurrency", conc_runs), ("streaming", stream_runs)):
        for run_id in runs:
            timed.append({"key": (t, run_id), "type": t, "run_id": run_id, "label": _timed_label(run_id, t)})
    # run_id is a sortable timestamp string on both sides (LEGACY_RUN_ID sorts
    # first, same quirk each individual selector already had on its own).
    timed.sort(key=lambda e: e["run_id"], reverse=True)
    entries.extend(timed)

    real_runs = [e for e in timed if e["run_id"] != LEGACY_RUN_ID]
    if real_runs:
        default_key = max(real_runs, key=lambda e: e["run_id"])["key"]
    elif timed:
        default_key = timed[0]["key"]
    else:
        default_key = None

    return entries, default_key


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
    """Concurrency-sweep significance table -- unchanged call, unchanged
    output: baseline_config auto-resolves to "control" (present in every
    concurrency-sweep run), so every existing number here is untouched."""
    if trimmed_df is None or trimmed_df.empty:
        return None
    return mann_whitney_vs_control(trimmed_df, metric=metric)


def get_streaming_significance(streaming_df: pd.DataFrame | None, metric: str = "ttft_ms") -> pd.DataFrame | None:
    """Streaming-run equivalent of get_significance() -- grouped by
    (strategy, max_tokens, chunk_size_tokens) instead of concurrency (the
    streaming sweep has no "concurrency" column), and baseline_config
    auto-resolves to "classical" since there's no "control" leg to compare
    against. Check the result's "baseline_config" column before labeling
    it -- this is a real methodological difference from the concurrency
    sweep's control-relative numbers, not a detail to hide."""
    if streaming_df is None or streaming_df.empty:
        return None
    return mann_whitney_vs_control(
        streaming_df, metric=metric, group_cols=("strategy", "max_tokens", "chunk_size_tokens")
    )


def build_custom_tradeoff(
    trimmed_df: pd.DataFrame, w_sec: float, w_perf: float,
    scale_col: str = "concurrency", metric_col: str = "rtt_ms",
    security_scores: dict[str, float | None] | None = None,
) -> pd.DataFrame:
    """Thin call-through into analysis.tradeoff_matrix.build_matrix_at -- the
    dashboard's interactive weighting slider needs a single arbitrary
    (w_sec, w_perf) pair rather than build_matrix()'s three fixed presets,
    but the score formula itself lives in exactly one place (tradeoff_matrix.py),
    not reimplemented here. baseline_config auto-resolves inside
    build_matrix_at (see its docstring) -- "control" for the concurrency
    sweep's default (scale_col="concurrency", metric_col="rtt_ms") call,
    "classical" for a streaming call (scale_col="max_tokens",
    metric_col="ttft_ms", say). Check the result's "baseline_config" column
    before labeling it.

    security_scores=None (default) uses the plain SECURITY_SCORES mapping,
    unchanged concurrency-sweep behavior. A streaming call passes a dict of
    {config: analysis.tradeoff_matrix.streaming_security_score(config,
    strategy, ...)} instead, pre-filtered to the configs with actual data --
    see build_matrix_at's docstring."""
    return build_matrix_at(
        trimmed_df, w_sec, w_perf, scale_col=scale_col, metric_col=metric_col, security_scores=security_scores
    )


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


def load_streaming_hndl_summaries() -> list[dict]:
    """threats/streaming_hndl_experiment.py's per-config length-sweep
    summaries (results/hndl/streaming/*-streaming-hndl-summary.json) -- kept
    in their own directory/loader, distinct from load_hndl_summaries()'s
    results/hndl/*-summary.json glob (non-recursive, so no collision) and
    from load_streaming_mitm_summaries(), since this is a confidentiality/HNDL
    finding, not the sequence-integrity one; see docs/STREAMING.md section 10
    for why the two must not be mixed into one chart or one AI-summary claim."""
    paths = sorted(glob.glob(os.path.join(STREAMING_HNDL_DIR, "*-streaming-hndl-summary.json")))
    out = []
    for p in paths:
        try:
            out.append(json.load(open(p)))
        except Exception:
            continue
    return out


def load_streaming_hndl_independence() -> list[dict]:
    """threats/streaming_hndl_experiment.py's per-config strategy-independence
    checks (results/hndl/streaming/*-strategy-independence.json) -- whether
    total_bytes_harvestable actually matched across signing strategies at one
    fixed response length, checked empirically rather than assumed."""
    paths = sorted(glob.glob(os.path.join(STREAMING_HNDL_DIR, "*-strategy-independence.json")))
    out = []
    for p in paths:
        try:
            out.append(json.load(open(p)))
        except Exception:
            continue
    return out


def load_sweep_summaries(run_id: str | None = None) -> pd.DataFrame:
    """Per-cell sweep summaries written by bench.orchestrator.run_full_sweep
    (per (config, concurrency, repetition) cell) and, since Fix 1,
    bench.streaming_runner.run_sweep (per streaming transaction) -- both
    include throughput/error info and server-process CPU%/RSS during that
    cell (crypto.instrumentation.ResourceSampler). One file per run_id under
    results/sweep_summaries/, since both sweeps share the same run_id
    generator. Runs from before resource sampling existed for their sweep
    type have no file and are simply absent here -- not an error, just no
    resource data for them.
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


def load_resource_summaries(run_type: str, run_id: str | None = None) -> pd.DataFrame:
    """load_sweep_summaries() scoped to one run_type ("concurrency" or
    "streaming") and, optionally, one run_id -- what the Results Dashboard's
    Resource Usage panel actually wants, for either mode, via one call.

    Every summary file written before this per-cell "run_type" tagging
    existed came only from bench.orchestrator's concurrency sweep --
    bench.streaming_runner never wrote to this directory before Fix 1 -- so
    a missing run_type is treated as "concurrency" rather than dropped or
    misfiled. That's what keeps every already-validated concurrency-sweep
    resource number unchanged by this function's existence."""
    df = load_sweep_summaries(run_id=run_id)
    if df.empty:
        return df
    df = df.copy()
    if "run_type" not in df.columns:
        df["run_type"] = "concurrency"
    else:
        df["run_type"] = df["run_type"].fillna("concurrency")
    return df[df["run_type"] == run_type].reset_index(drop=True)
