import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from webapp.bootstrap import load_dotenv_if_needed

load_dotenv_if_needed()

import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from plotly.subplots import make_subplots

from analysis import streaming_analysis
from webapp import data_loader as dl

st.set_page_config(page_title="PQ-Shield — Results Dashboard", page_icon="📊", layout="wide")
st.title("📊 Results Dashboard")

CONFIG_COLORS = {"control": "#888888", "classical": "#c0392b", "hybrid": "#e67e22", "full_pqc": "#2471a3"}

refresh = st.button("🔄 Refresh data")

all_runs, latest_run = dl.get_available_runs()

if not all_runs:
    st.warning(
        "No results/raw/*.csv found yet. Run the **Benchmark Runner** page, or "
        "`python -m bench.orchestrator` from the CLI, then come back and refresh."
    )
    st.stop()

ALL_RUNS_OPTION = "__all__"
run_options = [ALL_RUNS_OPTION] + all_runs
run_labels = {ALL_RUNS_OPTION: f"All runs combined ({len(all_runs)} runs)"}
run_labels.update({r: dl.run_label(r) for r in all_runs})

default_index = run_options.index(latest_run) if latest_run in run_options else 0
selected_run = st.selectbox(
    "Data source",
    options=run_options,
    index=default_index,
    format_func=lambda r: run_labels[r],
    help=(
        "results/raw/ accumulates every sweep ever run, with no automatic cleanup. "
        "Defaults to your most recent run; switch to 'All runs combined' to reproduce "
        "the CLI's analysis.aggregate behavior over everything on disk."
    ),
)

trimmed, summary = dl.get_trimmed_and_summary(
    warmup_fraction=0.05,
    run_id=None if selected_run == ALL_RUNS_OPTION else selected_run,
)

if trimmed is None:
    st.warning("No data in the selected run after warm-up trimming.")
    st.stop()

ok = trimmed[trimmed["error"].isna() | (trimmed["error"] == "")]
n_total = len(trimmed)
n_ok = len(ok)
n_errors = n_total - n_ok

m1, m2, m3, m4 = st.columns(4)
m1.metric("Total requests (post warm-up trim)", f"{n_total:,}")
m2.metric("Successful", f"{n_ok:,}")
m3.metric("Errors", f"{n_errors:,}", delta=f"{n_errors / n_total:.1%}" if n_total else None, delta_color="inverse")
m4.metric("Configurations present", trimmed["config"].nunique())

st.caption(
    "The first 5% of requests in each (config, concurrency, repetition) cell are discarded as "
    "connection-pool/JIT warm-up before any statistics below are computed, matching "
    "`analysis/aggregate.py`."
)

# ---------------------------------------------------------------------------
# RTT vs concurrency
# ---------------------------------------------------------------------------
st.divider()
st.subheader("RTT vs. Concurrency (RQ1)")

fig1 = go.Figure()
for config in dl.CONFIG_ORDER:
    sub = ok[ok["config"] == config]
    if sub.empty:
        continue
    grouped = sub.groupby("concurrency")["rtt_ms"]
    x = sorted(grouped.groups.keys())
    median = [grouped.get_group(c).median() for c in x]
    p95 = [grouped.get_group(c).quantile(0.95) for c in x]
    color = CONFIG_COLORS[config]
    fig1.add_trace(go.Scatter(x=x, y=median, mode="lines+markers", name=f"{dl.CONFIG_LABELS[config]} (median)",
                               line=dict(color=color)))
    fig1.add_trace(go.Scatter(x=x, y=p95, mode="lines+markers", name=f"{dl.CONFIG_LABELS[config]} (p95)",
                               line=dict(color=color, dash="dash"), opacity=0.6))
fig1.update_layout(xaxis_type="log", xaxis_title="Concurrency (log scale)", yaxis_title="RTT (ms)",
                    height=450, legend=dict(orientation="h", yanchor="bottom", y=-0.4))
st.plotly_chart(fig1, width='stretch')

# ---------------------------------------------------------------------------
# Overhead decomposition at a selectable concurrency
# ---------------------------------------------------------------------------
st.divider()
st.subheader("Where the Overhead Comes From")

available_concurrency = sorted(ok["concurrency"].unique())
sel_concurrency = st.select_slider("Concurrency level", options=available_concurrency,
                                    value=available_concurrency[len(available_concurrency) // 2])
sub = ok[ok["concurrency"] == sel_concurrency]
protected_configs = [c for c in ["classical", "hybrid", "full_pqc"] if c in sub["config"].unique()]

if protected_configs:
    metrics = [
        ("handshake_ms", "Handshake RTT"), ("server_decapsulate_ms", "Server decapsulate"),
        ("server_sign_ms", "Server sign"), ("verify_ms", "Client verify"),
    ]
    fig2 = go.Figure()
    for metric, label in metrics:
        if metric not in sub.columns:
            continue
        vals = [sub[sub["config"] == c][metric].median() for c in protected_configs]
        fig2.add_trace(go.Bar(name=label, x=[dl.CONFIG_LABELS[c] for c in protected_configs], y=vals))
    fig2.update_layout(barmode="group", yaxis_title="Median time (ms)", height=400,
                        title=f"Overhead decomposition at concurrency={sel_concurrency}")
    st.plotly_chart(fig2, width='stretch')
else:
    st.info("No protected-configuration data at this concurrency level yet.")

# ---------------------------------------------------------------------------
# Bytes per request
# ---------------------------------------------------------------------------
st.divider()
st.subheader("Wire Bytes per Request (RQ3)")

if protected_configs:
    kex_bytes = [ok[ok["config"] == c]["kex_blob_bytes"].dropna().median() for c in protected_configs]
    sig_bytes = [ok[ok["config"] == c]["signature_bytes"].dropna().median() for c in protected_configs]
    fig3 = go.Figure()
    fig3.add_trace(go.Bar(name="Key-establishment blob", x=[dl.CONFIG_LABELS[c] for c in protected_configs], y=kex_bytes))
    fig3.add_trace(go.Bar(name="Signature", x=[dl.CONFIG_LABELS[c] for c in protected_configs], y=sig_bytes))
    fig3.update_layout(barmode="stack", yaxis_title="Bytes per request", height=350)
    st.plotly_chart(fig3, width='stretch')
else:
    st.info("No protected-configuration byte data yet.")

# ---------------------------------------------------------------------------
# Server resource usage (CPU% / RSS per config, sampled during each cell)
# ---------------------------------------------------------------------------
st.divider()
st.subheader("Server Resource Usage")
st.caption(
    "Server-process CPU% and RSS sampled every 0.25s during each cell "
    "(crypto.instrumentation.ResourceSampler), attributed to the config whose server "
    "was running at the time -- not available for cells run before this was added, "
    "or for cells too short to catch a sample."
)

resource_df = dl.load_sweep_summaries(run_id=None if selected_run == ALL_RUNS_OPTION else selected_run)
resource_df = resource_df[resource_df["cpu_percent_mean"].notna()] if not resource_df.empty else resource_df

if resource_df.empty:
    st.info(
        "No resource-usage data for this selection -- either it predates resource sampling, "
        "or every cell was too short to catch a 0.25s sample."
    )
else:
    cpu_by_config = resource_df.groupby("config")["cpu_percent_mean"].mean()
    rss_by_config = resource_df.groupby("config")["rss_mb_mean"].mean()
    configs_present = [c for c in ["control", "classical", "hybrid", "full-pqc"] if c in cpu_by_config.index]
    fig_res = make_subplots(specs=[[{"secondary_y": True}]])
    fig_res.add_trace(go.Bar(name="Mean server CPU %", x=configs_present,
                              y=[cpu_by_config[c] for c in configs_present], marker_color="#c0392b"),
                       secondary_y=False)
    fig_res.add_trace(go.Scatter(name="Mean server RSS (MB)", x=configs_present,
                                  y=[rss_by_config[c] for c in configs_present],
                                  mode="markers+lines", marker=dict(size=10, color="#2471a3")),
                       secondary_y=True)
    fig_res.update_yaxes(title_text="CPU %", secondary_y=False)
    fig_res.update_yaxes(title_text="RSS (MB)", secondary_y=True)
    fig_res.update_layout(height=350)
    st.plotly_chart(fig_res, width='stretch')

# ---------------------------------------------------------------------------
# Streaming (SSE) response overhead -- separate data source (results/streaming/),
# not scoped by the run_id selector above since it's a different sweep entirely
# (bench.streaming_runner, not bench.orchestrator) -- see docs/STREAMING.md.
# ---------------------------------------------------------------------------
st.divider()
st.subheader("🌊 Streaming Response Overhead")
st.caption(
    "From `results/streaming/*.csv` (bench.streaming_runner — the Benchmark Runner page's "
    "'Streaming Sweep' tab, or `python -m bench.streaming_runner` from the CLI). Compares the "
    "three SSE signing strategies (crypto/streaming.py) on time-to-first-token and total "
    "signature-byte overhead, independent of the concurrency sweep above."
)

streaming_df = dl.load_streaming_df()

if streaming_df is None or streaming_df.empty:
    st.info(
        "No streaming sweep data yet. Run one from the **Benchmark Runner** page's "
        "'Streaming Sweep' tab, or `python -m bench.streaming_runner` from the CLI."
    )
else:
    streaming_ok = streaming_df[streaming_df["error"].isna() | (streaming_df["error"] == "")]
    n_stream_total = len(streaming_df)
    n_stream_errors = n_stream_total - len(streaming_ok)
    all_verified = bool(streaming_ok["stream_fully_verified"].astype(bool).all()) if len(streaming_ok) else None

    sm1, sm2, sm3 = st.columns(3)
    sm1.metric("Streaming transactions", f"{n_stream_total:,}")
    sm2.metric("Errors", f"{n_stream_errors:,}",
               delta=f"{n_stream_errors / n_stream_total:.1%}" if n_stream_total else None,
               delta_color="inverse")
    sm3.metric("All verified", "✅ Yes" if all_verified else ("❌ No" if all_verified is False else "—"))

    stream_summary = streaming_analysis.summarize(streaming_df)
    stream_configs_present = [c for c in dl.CONFIG_ORDER if c in stream_summary["config"].unique()]
    available_max_tokens = sorted(stream_summary["max_tokens"].unique())
    available_chunk_sizes = sorted(stream_summary["chunk_size_tokens"].unique())

    sc1, sc2 = st.columns(2)
    with sc1:
        sel_max_tokens = st.select_slider(
            "Response length (max tokens)", options=available_max_tokens, value=available_max_tokens[-1],
        )
    with sc2:
        sel_chunk_size = st.select_slider("Chunk size (tokens)", options=available_chunk_sizes,
                                           value=available_chunk_sizes[0])

    slice_df = stream_summary[
        (stream_summary["max_tokens"] == sel_max_tokens) & (stream_summary["chunk_size_tokens"] == sel_chunk_size)
    ]
    STRATEGY_COLORS = {"buffer_and_sign": "#888888", "per_chunk": "#c0392b", "hash_chain": "#2471a3"}
    STRATEGY_ORDER = ["buffer_and_sign", "per_chunk", "hash_chain"]

    if slice_df.empty or not stream_configs_present:
        st.info("No streaming rows at this response length / chunk size combination.")
    else:
        col_ttft, col_sig = st.columns(2)

        with col_ttft:
            fig_ttft = go.Figure()
            for strategy in STRATEGY_ORDER:
                sub = slice_df[slice_df["strategy"] == strategy]
                sub = sub.set_index("config").reindex(stream_configs_present)
                fig_ttft.add_trace(go.Bar(
                    name=strategy, x=[dl.CONFIG_LABELS[c] for c in stream_configs_present],
                    y=sub["ttft_ms_mean"], marker_color=STRATEGY_COLORS[strategy],
                ))
            fig_ttft.update_layout(
                barmode="group", yaxis_title="Time to first token (ms)", height=380,
                title=f"TTFT at {sel_max_tokens} max tokens, chunk={sel_chunk_size}",
                legend=dict(orientation="h", yanchor="bottom", y=-0.35),
            )
            st.plotly_chart(fig_ttft, width='stretch')

        with col_sig:
            fig_sig = go.Figure()
            for strategy in STRATEGY_ORDER:
                sub = slice_df[slice_df["strategy"] == strategy]
                sub = sub.set_index("config").reindex(stream_configs_present)
                fig_sig.add_trace(go.Bar(
                    name=strategy, x=[dl.CONFIG_LABELS[c] for c in stream_configs_present],
                    y=sub["total_signature_bytes_mean"], marker_color=STRATEGY_COLORS[strategy],
                ))
            fig_sig.update_layout(
                barmode="group", yaxis_title="Total signature bytes (log scale)", yaxis_type="log", height=380,
                title=f"Signature overhead at {sel_max_tokens} max tokens, chunk={sel_chunk_size}",
                legend=dict(orientation="h", yanchor="bottom", y=-0.35),
            )
            st.plotly_chart(fig_sig, width='stretch')

    st.markdown("**Strategy comparison** (speedup / byte-reduction relative to the baseline strategies)")
    highlight_config = st.selectbox(
        "Configuration", stream_configs_present,
        format_func=lambda c: dl.CONFIG_LABELS.get(c, c), key="stream_highlight_config",
    )
    comparison = streaming_analysis.strategy_comparison_at(
        streaming_df, highlight_config, sel_max_tokens, sel_chunk_size
    )
    if comparison.empty:
        st.info("No rows for this exact (configuration, response length, chunk size) combination.")
    else:
        st.dataframe(
            comparison.style.format({
                "ttft_ms_mean": "{:.1f}",
                "ttft_speedup_vs_buffer_and_sign": "{:.2f}x",
                "total_signature_bytes_mean": "{:,.0f}",
                "signature_bytes_reduction_vs_per_chunk": "{:.1%}",
            }, na_rep="—"),
            width='stretch',
        )

    with st.expander("Full streaming summary table"):
        st.dataframe(stream_summary, width='stretch')

# ---------------------------------------------------------------------------
# Cryptographic validation -- ground-truth checks independent of the
# benchmark sweeps above: NIST's own ACVP known-answer vectors for the raw
# primitives, and an analytical signature-cost model for the streaming
# result (see docs/STREAMING.md sections 9-10 for the full methodology).
# ---------------------------------------------------------------------------
st.divider()
st.subheader("🔬 Cryptographic Validation")
st.caption(
    "Ground-truth checks, not benchmark results: do PQ-Shield's own liboqs bindings match NIST's "
    "official test vectors, and does the streaming signature-cost harness measure exactly what "
    "the signing strategies' own arithmetic says it should?"
)

vc1, vc2 = st.columns(2)

with vc1:
    st.markdown("**NIST ACVP Known-Answer Tests** (ML-KEM-768 / ML-DSA-65 vs. NIST's own vectors)")
    try:
        from validation.nist_kat import run_all as run_nist_kat

        with st.spinner("Running KAT vectors..."):
            kat_results = run_nist_kat()
        kat_summary = kat_results["summary"]
        k1, k2 = st.columns(2)
        k1.metric("Vectors passed", f"{kat_summary['passed']}/{kat_summary['total_checks']}")
        k2.metric("All pass?", "✅ Yes" if kat_summary["all_passed"] else "❌ No")
        st.dataframe(
            [
                {"check": "ML-KEM-768 keyGen", "passed": kat_results["ml_kem_768_keygen"]["passed"],
                 "total": kat_results["ml_kem_768_keygen"]["total"]},
                {"check": "ML-KEM-768 encapsulation", "passed": kat_results["ml_kem_768_encap_decap"]["encapsulation"]["passed"],
                 "total": kat_results["ml_kem_768_encap_decap"]["encapsulation"]["total"]},
                {"check": "ML-KEM-768 decapsulation", "passed": kat_results["ml_kem_768_encap_decap"]["decapsulation"]["passed"],
                 "total": kat_results["ml_kem_768_encap_decap"]["decapsulation"]["total"]},
                {"check": "ML-DSA-65 signature verification", "passed": kat_results["ml_dsa_65_sigver"]["passed"],
                 "total": kat_results["ml_dsa_65_sigver"]["total"]},
            ],
            width='stretch', hide_index=True,
        )
        with st.expander("Not achievable through liboqs's public API (documented, not skipped)"):
            st.json(kat_results["not_achievable"])
        with st.expander("Full KAT results JSON"):
            st.json(kat_results)
    except Exception as exc:
        st.warning(f"NIST KAT check unavailable: {exc}")

with vc2:
    st.markdown("**Streaming Signature-Cost Model Validation** (measured vs. predicted from primitive costs)")
    primitive_bench_path = os.path.join(dl.REPO_ROOT, "results", "validation", "primitive_bench.json")
    if streaming_df is None or streaming_df.empty:
        st.info("No streaming sweep data yet -- see the streaming section above.")
    elif not os.path.isfile(primitive_bench_path):
        st.info(
            f"No `{os.path.relpath(primitive_bench_path, dl.REPO_ROOT)}` yet -- run "
            "`python -m validation.primitive_bench --output results/validation/primitive_bench.json` first."
        )
    else:
        try:
            from analysis.streaming_model_validation import run_validation as run_streaming_model_validation

            with st.spinner("Validating measured signature bytes/timing against the analytical model..."):
                mv = run_streaming_model_validation(dl.STREAMING_DIR, primitive_bench_path)
            mvs = mv["summary"]
            mv1, mv2, mv3 = st.columns(3)
            mv1.metric("Bytes: exact/in-range", f"{mvs['bytes_ok']}/{mvs['validated_rows']}",
                       delta="ALL OK" if mvs["bytes_all_ok"] else "mismatches", delta_color="off")
            mv2.metric("Timing (warm-loop baseline)", f"{mvs['timing_ok']}/{mvs['validated_rows']}")
            mv3.metric("Timing (best applicable baseline)", f"{mvs['timing_ok_best']}/{mvs['validated_rows']}")
            st.dataframe(mv["per_group"], width='stretch', hide_index=True)
            st.caption(
                "'Best applicable baseline' uses a cold-start-process correction for "
                "`buffer_and_sign` (see docs/STREAMING.md section 9 for why ECDSA specifically "
                "needs one and ML-DSA-65 doesn't) and the ordinary warm-loop mean elsewhere. "
                "Byte agreement is the strongest, fully-validated claim regardless of the timing "
                "baseline used."
            )
            with st.expander("Full validation results JSON (per-row detail)"):
                st.json(mv)
        except Exception as exc:
            st.warning(f"Streaming model validation unavailable: {exc}")

# ---------------------------------------------------------------------------
# Aggregate stats + significance tables
# ---------------------------------------------------------------------------
st.divider()
st.subheader("Aggregate Statistics")
st.dataframe(summary, width='stretch')

sig = dl.get_significance(trimmed)
st.subheader("Mann-Whitney U Test vs. Control (RTT)")
if sig is None or sig.empty:
    st.info("Need at least a 'control' configuration and one protected configuration at the same "
            "concurrency level to compute significance.")
else:
    st.dataframe(
        sig.style.format({
            "median_control": "{:.2f}", "median_treatment": "{:.2f}",
            "overhead_pct_vs_control": "{:.1f}%", "p_value": "{:.4g}",
        }),
        width='stretch',
    )

# ---------------------------------------------------------------------------
# Interactive trade-off matrix
# ---------------------------------------------------------------------------
st.divider()
st.subheader("Security / Performance Trade-off Matrix (Layer 6)")
st.caption(
    "composite_score = w_sec x security_score(config) - w_perf x normalized_latency_overhead. "
    "security_score: classical=0.0, hybrid=0.8, full_pqc=1.0 — see docs/DESIGN.md for the justification."
)

w_sec = st.slider("Security weight (w_sec)", 0.0, 1.0, 0.5, 0.05)
w_perf = 1.0 - w_sec
st.caption(f"Performance weight (w_perf) = {w_perf:.2f} (linked to w_sec so weights sum to 1)")

matrix = dl.build_custom_tradeoff(trimmed, w_sec, w_perf)

if matrix.empty:
    st.info("Need at least one protected configuration and 'control' at a shared concurrency level.")
else:
    pivot = matrix.pivot(index="config", columns="concurrency", values="composite_score")
    pivot = pivot.reindex([c for c in ["classical", "hybrid", "full_pqc"] if c in pivot.index])

    fig6 = px.imshow(
        pivot.values, x=[str(c) for c in pivot.columns], y=[dl.CONFIG_LABELS[c] for c in pivot.index],
        color_continuous_scale="RdYlGn", text_auto=".2f", aspect="auto",
        labels=dict(x="Concurrency", y="Configuration", color="Composite score"),
    )
    fig6.update_layout(height=350)
    st.plotly_chart(fig6, width='stretch')

    best_per_concurrency = matrix.loc[matrix.groupby("concurrency")["composite_score"].idxmax()]
    st.markdown("**Recommended configuration per concurrency level, at this weighting:**")
    st.dataframe(
        best_per_concurrency[["concurrency", "config", "composite_score", "normalized_latency_overhead"]]
        .assign(config=lambda d: d["config"].map(dl.CONFIG_LABELS))
        .style.format({"composite_score": "{:.3f}", "normalized_latency_overhead": "{:.1%}"}),
        width='stretch',
    )

# ---------------------------------------------------------------------------
# AI summary
# ---------------------------------------------------------------------------
st.divider()
st.subheader("🤖 AI Summary")

from webapp import ai_summary

if not ai_summary.api_key_present():
    st.info(
        "Set `ANTHROPIC_API_KEY` in `.env` (repo root) to enable an AI-generated "
        "summary of the results above."
    )
else:
    st.caption(
        "Sends the aggregate statistics, significance tests, and trade-off matrix "
        "shown above (not raw per-request rows) to Claude for a plain-language summary."
    )
    if st.button("Generate AI summary", type="primary"):
        context = ai_summary.build_dashboard_context(
            n_total=n_total,
            n_ok=n_ok,
            n_errors=n_errors,
            summary_df=summary,
            significance_df=sig,
            tradeoff_df=matrix if not matrix.empty else None,
            w_sec=w_sec,
            resource_df=resource_df if not resource_df.empty else None,
        )
        try:
            with st.spinner("Asking Claude..."):
                text = ai_summary.generate_dashboard_summary(context)
            st.markdown(text)
        except Exception as exc:
            st.error(f"AI summary failed: {exc}")
