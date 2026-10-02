import json

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from analysis import streaming_analysis
from analysis.aggregate import summarize as summarize_cells
from webapp import chart_explainer, ui
from webapp import data_loader as dl
from webapp import findings as fd
from webapp.colors import CONFIG_COLORS, CONFIG_COLORS_HYPHENATED, STRATEGY_COLORS, STRATEGY_ORDER

ui.page_header(
    "Results explorer",
    "Browse any concurrency or streaming run on disk — including quick runs from the Benchmark runner. "
    "For the paper's own runs with full statistics, see Key findings.",
    eyebrow="Evidence",
)

STRAT_LABEL = {"buffer_and_sign": "Buffer & sign", "per_chunk": "Per-chunk", "hash_chain": "Hash chain"}

run_entries, default_key = dl.get_unified_runs()
if not run_entries:
    ui.empty_state("No results yet.", "Run a sweep from the Benchmark runner page, or `python -m bench.paper_runs`.")
    st.stop()

entry_by_key = {e["key"]: e for e in run_entries}
options = [e["key"] for e in run_entries]
# The paper's concurrency data combine several runs (corrective re-runs supersede
# earlier ones per configuration); offer exactly that view first, and default to it.
_paper_ids = tuple(fd.concurrency_run_ids())
if _paper_ids:
    _pk = ("concurrency", "__paper__")
    entry_by_key[_pk] = {"key": _pk, "type": "concurrency", "run_id": "__paper__",
                         "label": "Paper runs — latest run per configuration (as in the paper)"}
    options = [_pk] + options
    default_key = _pk
top_l, top_r = st.columns([4, 1])
with top_l:
    selected_key = st.selectbox("Data source", options, index=options.index(default_key) if default_key in options else 0,
                                format_func=lambda k: entry_by_key[k]["label"])
with top_r:
    st.write("")
    if st.button("Refresh", icon=":material/refresh:", width="stretch"):
        st.cache_data.clear()
selected = entry_by_key[selected_key]
mode, run_id = selected["type"], selected["run_id"]


@st.cache_data(show_spinner=False)
def _rep_comparisons(df: pd.DataFrame, reference: str) -> pd.DataFrame:
    from analysis.paper_figures import comparison_stats

    present = [c for c in ui.CONFIG_ORDER if c in set(df["config"]) and c != reference]
    return comparison_stats(df, [(c, reference) for c in present])


# ================================================================================ concurrency
if mode == "concurrency":
    if run_id == "__paper__":
        with st.spinner("Loading the paper's runs…"):
            trimmed = fd.paper_concurrency_df(_paper_ids)
        summary = summarize_cells(trimmed) if trimmed is not None else None
    else:
        trimmed, summary = dl.get_trimmed_and_summary(warmup_fraction=0.05, run_id=run_id)
    if trimmed is None:
        ui.empty_state("No data in this run after warm-up trimming.")
        st.stop()
    ok = trimmed[trimmed["error"].isna() | (trimmed["error"] == "")]
    n_total, n_ok = len(trimmed), len(ok)
    ui.kpi_cards([
        {"label": "Requests (after 5% warm-up trim)", "value": f"{n_total:,}"},
        {"label": "Failed", "value": f"{n_total - n_ok:,}", "sub": f"{(n_total - n_ok) / n_total:.2%} of requests"},
        {"label": "Configurations", "value": trimmed["config"].nunique()},
        {"label": "Concurrency levels", "value": ", ".join(f"{int(c):,}" for c in sorted(trimmed["concurrency"].unique()))},
    ])

    ui.section("End-to-end latency vs. concurrency", "Handshake + protected request — the cost a client pays. "
               "Median with interquartile range.")
    fig = go.Figure()
    series = {}
    for cfg in ui.CONFIG_ORDER:
        sub = ok[ok["config"] == cfg]
        if sub.empty:
            continue
        g = sub.groupby("concurrency")["total_ms"]
        x = sorted(g.groups)
        med = [g.get_group(c).median() for c in x]
        q1 = [g.get_group(c).quantile(0.25) for c in x]
        q3 = [g.get_group(c).quantile(0.75) for c in x]
        fig.add_trace(go.Scatter(x=x, y=med, mode="lines+markers", name=ui.SHORT[cfg], line=dict(color=CONFIG_COLORS[cfg]),
                                 error_y=dict(type="data", symmetric=False, array=np.subtract(q3, med),
                                              arrayminus=np.subtract(med, q1), thickness=1)))
        series[cfg] = {"concurrency": x, "median_ms": med}
    fig.update_xaxes(type="category", title="Concurrent connections")
    fig.update_yaxes(type="log", title="End-to-end latency (ms)")
    ui.chart(ui.style_fig(fig, 430))
    chart_explainer.render_explain_button(chart_key=f"lat:{selected_key}", chart_title="End-to-end latency vs concurrency",
                                          chart_data={"series_by_config": series})

    levels = sorted(ok["concurrency"].unique())
    sel_c = st.select_slider("Concurrency level for the panels below", options=levels,
                             value=levels[0], format_func=lambda c: f"{int(c):,}")
    sub = ok[ok["concurrency"] == sel_c]
    prot = [c for c in ui.PROTECTED if c in set(sub["config"])]
    l, r = st.columns(2)
    with l:
        ui.section("Where the time goes", f"Median per phase at {int(sel_c):,} connections")
        if prot:
            fig = go.Figure()
            for metric, name, color in (("handshake_ms", "Handshake round trip", "#4f46e5"),
                                        ("server_decapsulate_ms", "Server decapsulate", "#2f5d8a"),
                                        ("server_sign_ms", "Server sign", "#c9822b"),
                                        ("verify_ms", "Client verify", "#16a085")):
                if metric in sub:
                    fig.add_trace(go.Bar(x=[ui.SHORT[c] for c in prot],
                                         y=[sub[sub["config"] == c][metric].median() for c in prot],
                                         name=name, marker_color=color))
            fig.update_layout(barmode="group")
            fig.update_yaxes(type="log", title="ms (log)")
            ui.chart(ui.style_fig(fig, 340))
    with r:
        ui.section("Bytes on the wire", "Key-exchange blob and signature per request")
        if prot:
            fig = go.Figure()
            fig.add_trace(go.Bar(x=[ui.SHORT[c] for c in prot], y=[ok[ok["config"] == c]["kex_blob_bytes"].median() for c in prot],
                                 name="Key-exchange blob", marker_color="#2f5d8a"))
            fig.add_trace(go.Bar(x=[ui.SHORT[c] for c in prot], y=[ok[ok["config"] == c]["signature_bytes"].median() for c in prot],
                                 name="Signature", marker_color="#c9822b"))
            fig.update_layout(barmode="stack")
            fig.update_yaxes(title="Bytes")
            ui.chart(ui.style_fig(fig, 340))

    res = fd.paper_resources(_paper_ids) if run_id == "__paper__" else \
        dl.load_resource_summaries("concurrency", run_id=run_id)
    if not res.empty and res["cpu_percent_mean"].notna().any():
        res = res[res["cpu_percent_mean"].notna()].assign(cfg=lambda d: d["config"].map(dl.HYPHEN_TO_CRYPTO))
        ui.section("Server CPU", "Mean cores in use (100% = one core) per configuration and concurrency")
        fig = go.Figure()
        for cfg in [c for c in ui.CONFIG_ORDER if c in set(res["cfg"])]:
            g = res[res["cfg"] == cfg].groupby("concurrency")["cpu_percent_mean"].mean() / 100
            fig.add_trace(go.Bar(x=[f"{int(c):,}" for c in g.index], y=g.values, name=ui.SHORT[cfg],
                                 marker_color=CONFIG_COLORS[cfg]))
        fig.update_layout(barmode="group")
        fig.update_xaxes(type="category", title="Concurrent connections")
        fig.update_yaxes(title="Cores")
        ui.chart(ui.style_fig(fig, 320))

    ui.section("Differences between configurations",
               "Repetition-level statistics: difference in medians with a two-stage bootstrap 95% CI, Cliff's δ, "
               "and a Mann–Whitney test on per-repetition medians (Holm-corrected). Needs ≥2 repetitions.")
    ref_opts = [c for c in ("control_2rt", "control", "classical_ecdhe") if c in set(trimmed["config"])]
    if ref_opts and trimmed.groupby(["config", "concurrency"])["repetition"].nunique().min() >= 2:
        ref = st.segmented_control("Compare against", ref_opts, default=ref_opts[0], format_func=ui.SHORT.get) or ref_opts[0]
        with st.spinner("Bootstrapping…"):
            cmp = _rep_comparisons(trimmed, ref)
        if not cmp.empty:
            show = cmp.assign(Configuration=cmp["config"].map(ui.label),
                              CI=lambda d: d.apply(lambda r: f"[{r['ci95_lo']:+.1f}, {r['ci95_hi']:+.1f}]", axis=1))
            st.dataframe(
                show[["concurrency", "Configuration", "diff_ms", "CI", "diff_pct", "cliffs_delta", "p_holm"]],
                hide_index=True, width="stretch",
                column_config={"concurrency": st.column_config.NumberColumn("Conc.", format="%d"),
                               "diff_ms": st.column_config.NumberColumn("Δ median (ms)", format="%+.1f"),
                               "CI": "95% CI (ms)",
                               "diff_pct": st.column_config.NumberColumn("Δ (%)", format="%+.1f%%"),
                               "cliffs_delta": st.column_config.NumberColumn("Cliff's δ", format="%+.2f"),
                               "p_holm": st.column_config.NumberColumn("p (Holm)", format="%.3f")})
            st.caption("At high concurrency on a single host, differences mostly reflect client–server contention.")
    else:
        st.caption("Not enough repetitions (or no reference configuration) in this run.")

    with st.expander("Per-cell summary table"):
        st.dataframe(summary, width="stretch", hide_index=True)

    from webapp import ai_summary

    if ai_summary.api_key_present():
        with st.expander("AI summary", icon=":material/auto_awesome:"):
            if st.button("Generate", key="ai_gen"):
                ctx = ai_summary.build_dashboard_context(n_total=n_total, n_ok=n_ok, n_errors=n_total - n_ok,
                                                         summary_df=summary, significance_df=None, tradeoff_df=None,
                                                         w_sec=0.5, resource_df=res if not res.empty else None)
                try:
                    with st.spinner("Asking Claude…"):
                        st.markdown(ai_summary.generate_dashboard_summary(ctx))
                except Exception as exc:
                    st.error(f"AI summary failed: {exc}")

# ================================================================================ streaming
else:
    sdf = dl.load_streaming_df(run_id=run_id)
    if sdf is None or sdf.empty:
        ui.empty_state("No data in this streaming run.")
        st.stop()
    ok = sdf[sdf["error"].isna() | (sdf["error"] == "")]
    verified = ok["stream_fully_verified"].astype(bool).mean() if len(ok) else 0
    backend = sdf["backend"].iloc[0] if "backend" in sdf else "unknown"
    ui.kpi_cards([
        {"label": "Streaming transactions", "value": f"{len(sdf):,}"},
        {"label": "Fully verified", "value": f"{verified:.0%}"},
        {"label": "Backend", "value": "Llama-3.2-3B" if backend == "llama_cpp" else backend},
        {"label": "Configurations", "value": sdf["config"].nunique()},
    ])
    has_k = "checkpoint_interval" in ok and ok["checkpoint_interval"].notna().any()
    plain = ok[ok["checkpoint_interval"].isna()] if "checkpoint_interval" in ok else ok
    if plain.empty:
        plain = ok
    lengths = sorted(plain["max_tokens"].unique())
    n_tok = st.select_slider("Response length", options=lengths, value=lengths[-1], format_func=lambda n: f"{n} tokens")
    sel = plain[plain["max_tokens"] == n_tok]
    present = [c for c in ui.PROTECTED if c in set(sel["config"])]

    l, r = st.columns(2)
    with l:
        ui.section("Time to first token", "Median with interquartile range")
        fig = go.Figure()
        for s in STRATEGY_ORDER:
            g = sel[sel["strategy"] == s]
            if g.empty:
                continue
            med = [g[g["config"] == c]["ttft_ms"].median() for c in present]
            fig.add_trace(go.Bar(x=[ui.SHORT[c] for c in present], y=med, name=STRAT_LABEL[s], marker_color=STRATEGY_COLORS[s]))
        fig.update_layout(barmode="group")
        fig.update_yaxes(type="log", title="ms (log)")
        ui.chart(ui.style_fig(fig, 340))
    with r:
        ui.section("Signature bytes per response")
        fig = go.Figure()
        for s in STRATEGY_ORDER:
            g = sel[sel["strategy"] == s]
            if g.empty:
                continue
            fig.add_trace(go.Bar(x=[ui.SHORT[c] for c in present],
                                 y=[g[g["config"] == c]["total_signature_bytes"].median() for c in present],
                                 name=STRAT_LABEL[s], marker_color=STRATEGY_COLORS[s]))
        fig.update_layout(barmode="group")
        fig.update_yaxes(type="log", title="Bytes (log)")
        ui.chart(ui.style_fig(fig, 340))

    if "total_signing_cpu_ms" in sel and sel["total_signing_cpu_ms"].notna().any():
        ui.section("Signing cost per signature", "Server thread-CPU time per signature, median over repetitions. "
                   "Depends on processor power state between chunks — see Key findings › Signing cost.")
        fig = go.Figure()
        for s in STRATEGY_ORDER:
            g = sel[(sel["strategy"] == s) & (sel["n_signatures"] > 0)]
            if g.empty:
                continue
            fig.add_trace(go.Bar(x=[ui.SHORT[c] for c in present],
                                 y=[(g[g["config"] == c]["total_signing_cpu_ms"] / g[g["config"] == c]["n_signatures"]).median() * 1000
                                    for c in present], name=STRAT_LABEL[s], marker_color=STRATEGY_COLORS[s]))
        fig.update_layout(barmode="group")
        fig.update_yaxes(title="µs per signature")
        ui.chart(ui.style_fig(fig, 320))

    if has_k:
        ui.section("Checkpoint intervals in this run")
        hc = ok[ok["strategy"] == "hash_chain"].assign(k=lambda d: d["checkpoint_interval"].fillna(0).astype(int))
        tab = hc.groupby(["config", "k"]).agg(signatures=("n_signatures", "median"), bytes=("total_signature_bytes", "median"),
                                             exposure_chunks=("max_unverified_chunks", "median"),
                                             lag_ms=("max_verification_lag_ms", "median")).reset_index()
        tab["config"] = tab["config"].map(ui.label)
        tab["k"] = tab["k"].map(lambda k: "∞" if k == 0 else str(k))
        st.dataframe(tab, hide_index=True, width="stretch",
                     column_config={"bytes": st.column_config.NumberColumn("Signature bytes", format="%,.0f"),
                                    "lag_ms": st.column_config.NumberColumn("Max verification lag (ms)", format="%,.0f")})

    with st.expander("Per-cell summary table"):
        st.dataframe(streaming_analysis.summarize(sdf), width="stretch", hide_index=True)
    st.caption("Generation speed can drift over a long run (thermal), so compare times within a configuration.")
