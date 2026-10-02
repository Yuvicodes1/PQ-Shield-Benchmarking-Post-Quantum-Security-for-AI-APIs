"""Cached data for the Key Findings page: the paper's own runs (named in
results/paper_runs.json) passed through the same functions that build the
paper's tables (analysis/paper_figures.py), so the page and the paper always
agree. Bootstrapped statistics are expensive, so they are cached to disk.
"""

from __future__ import annotations

import os

import numpy as np
import pandas as pd
import streamlit as st

from webapp import data_loader as dl

RESULTS = os.path.join(dl.REPO_ROOT, "results")


def _pf():
    from analysis import paper_figures  # heavy import (matplotlib), deferred
    return paper_figures


def concurrency_run_ids() -> list[str]:
    m = dl.load_manifest()
    return [r for r in (m.get("concurrency"), m.get("concurrency_supplement"), m.get("concurrency_control_2rt"),
                        m.get("concurrency_hybrid_kex_pq")) if r]


@st.cache_data(show_spinner=False, persist="disk")
def concurrency(run_ids: tuple[str, ...]) -> dict | None:
    if not run_ids:
        return None
    pf = _pf()
    try:
        df, _, _ = pf.load_concurrency(RESULTS, list(run_ids), 0.05)
    except SystemExit:
        return None
    st_ = pf.concurrency_stats(df)
    # Same pairs, in the same order, as analysis.paper_figures.main(): the bootstrap
    # draws depend on the order, so this reproduces the paper's intervals exactly.
    present = set(df["config"])
    pairs = [(c, "control") for c in pf.CONFIGS if c != "control" and c in present]
    if "control_2rt" in present:
        pairs += [(c, "control_2rt") for c in pf.PROTECTED if c in present]
    if "classical_ecdhe" in present:
        pairs += [(c, "classical_ecdhe") for c in ("hybrid", "hybrid_kex", "full_pqc", "hybrid_kex_pq") if c in present]
    cmp = pf.comparison_stats(df, pairs)
    is_err = df["error"].notna() & (df["error"] != "")
    fail = (df[is_err].assign(stage=lambda d: np.where(d["handshake_ms"].isna() & (d["config"] != "control"),
                                                      "handshake", "request"))
            .groupby(["config", "concurrency", "stage"]).size().rename("n").reset_index())
    return {"stats": st_, "cmp": cmp, "fail": fail}


@st.cache_data(show_spinner=False, persist="disk")
def dominance(run_ids: tuple[str, ...], streaming_run: str | None) -> dict | None:
    if not run_ids:
        return None
    pf = _pf()
    try:
        df, _, _ = pf.load_concurrency(RESULTS, list(run_ids), 0.05)
    except SystemExit:
        return None
    sdf = streaming(streaming_run)
    d = pf.dominance_frame(df, sdf, RESULTS)
    return {k: v for k, v in d.items() if k != "workloads"}


@st.cache_data(show_spinner=False)
def streaming(run_id: str | None) -> pd.DataFrame | None:
    if not run_id:
        return None
    pf = _pf()
    try:
        return pf.load_streaming(RESULTS, run_id)
    except SystemExit:
        return None


@st.cache_data(show_spinner=False, persist="disk")
def auth_cost(entries: tuple[tuple[str, bool, str], ...]) -> pd.DataFrame | None:
    """Back-to-back pairs (config, auth, run_id) from paper_runs step 20."""
    if not entries:
        return None
    pf = _pf()
    raw = pf.load_raw(os.path.join(RESULTS, "raw"))
    ids = {e[2] for e in entries}
    df = pf.discard_warmup(raw[raw["run_id"].astype(str).isin(ids)].reset_index(drop=True), 0.05)
    if df.empty:
        return None
    auth = df["auth_handshake"].fillna(False).astype(str).str.lower().isin(["true", "1"])
    df = df.assign(config=np.where(auth, df["config"] + "+auth", df["config"]))
    present = [c for c in pf.PROTECTED if c in set(df["config"]) and f"{c}+auth" in set(df["config"])]
    cmp = pf.comparison_stats(df, [(f"{c}+auth", c) for c in present], seed=19)
    ok = pf._ok(df)
    rows = []
    for c in present:
        r = cmp[cmp["config"] == f"{c}+auth"]
        rows.append({
            "config": c,
            "verify_us": ok[ok["config"] == f"{c}+auth"]["handshake_auth_verify_ms"].median() * 1000,
            "extra_bytes": 3309 if c in ("full_pqc", "hybrid_kex_pq") else 71,
            "diff_ms": r["diff_ms"].iloc[0] if not r.empty else np.nan,
            "lo": r["ci95_lo"].iloc[0] if not r.empty else np.nan,
            "hi": r["ci95_hi"].iloc[0] if not r.empty else np.nan,
        })
    return pd.DataFrame(rows)


def campaign_frame() -> pd.DataFrame | None:
    doc = dl.load_campaign()
    if not doc:
        return None
    df = pd.DataFrame(doc["rows"])
    df["k"] = df["checkpoint_interval"].fillna(0).astype(int)
    df.attrs.update({k: doc.get(k) for k in ("trials", "pool", "max_tokens", "backend")})
    return df


def signature_bytes(n_tokens: int, chunk: int, k: int | None, sig_bytes: int) -> tuple[int, int, int]:
    """Analytic model: (signatures, bytes, max exposure in tokens) for a hash
    chain checkpointed every k chunks (k=None: terminal signature only)."""
    n_chunks = int(np.ceil(n_tokens / chunk))
    n_sig = (n_chunks // k + 1) if k else 1
    exposure = (k * chunk) if k else n_chunks * chunk
    return n_sig, n_sig * sig_bytes, min(exposure, n_tokens)


@st.cache_data(show_spinner=False)
def paper_concurrency_df(run_ids: tuple[str, ...]) -> pd.DataFrame | None:
    """The paper's concurrency data: its runs combined, latest run per
    configuration (so corrective re-runs supersede earlier ones), warm-up trimmed."""
    if not run_ids:
        return None
    try:
        df, _, _ = _pf().load_concurrency(RESULTS, list(run_ids), 0.05)
    except SystemExit:
        return None
    return df


def paper_resources(run_ids: tuple[str, ...]) -> pd.DataFrame:
    res = dl.load_sweep_summaries()
    if res.empty or "run_id" not in res:
        return res
    res = res[res["run_id"].astype(str).isin(run_ids)]
    if "run_type" in res:
        res = res[res["run_type"].fillna("concurrency") == "concurrency"]
    latest = res.groupby("config")["run_id"].transform("max")
    return res[res["run_id"] == latest].reset_index(drop=True)
