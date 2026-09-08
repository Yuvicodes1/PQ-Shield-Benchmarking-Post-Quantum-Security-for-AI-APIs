import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from webapp.bootstrap import load_dotenv_if_needed

load_dotenv_if_needed()

import json

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from plotly.subplots import make_subplots

from analysis import streaming_analysis
from analysis.tradeoff_matrix import DEFAULT_EXPOSURE_SHARE, streaming_security_score
from webapp import chart_explainer, data_loader as dl
from webapp.colors import CONFIG_COLORS, STRATEGY_COLORS, STRATEGY_ORDER

st.set_page_config(page_title="PQ-Shield — Results Dashboard", page_icon="📊", layout="wide")
st.title("📊 Results Dashboard")

# ---------------------------------------------------------------------------
# Plain-language explainer -- every section heading below assumes the reader
# already knows RQ1/RQ3/"Layer 6"; this is the one place that spells them
# out, so a first-time reader doesn't need docs/DESIGN.md open to follow along.
# ---------------------------------------------------------------------------
st.markdown(
    "This dashboard measures what it actually costs, in milliseconds and bytes, to protect an "
    "AI inference API against a quantum-capable attacker — comparing an unprotected **control** "
    "against **classical** (RSA + ECDSA), **hybrid** (ML-KEM + ECDSA), and **full PQC** "
    "(ML-KEM + ML-DSA) configurations. **RQ1** is \"how much latency overhead does each "
    "configuration add as traffic scales up?\"; **RQ3** is \"how many extra bytes does each "
    "configuration put on the wire?\". **\"Layer 6\"** is this page's trade-off matrix further "
    "down: one composite score per configuration that weighs its quantum-resistance benefit "
    "against its measured latency cost, so you can see which configuration wins at your own "
    "risk tolerance without having to read the raw charts yourself."
)

refresh = st.button("🔄 Refresh data")

# ---------------------------------------------------------------------------
# Unified data-source selector -- one chronologically-sorted list covering
# both the concurrency sweep (results/raw/) and the streaming sweep
# (results/streaming/), interleaved rather than grouped by type. Everything
# below auto-detects which kind of run was picked and renders the matching
# panel content -- no separate mode toggle, no second selector.
# ---------------------------------------------------------------------------
run_entries, default_key = dl.get_unified_runs()

if not run_entries:
    st.warning(
        "No results/raw/*.csv or results/streaming/*.csv found yet. Run the **Benchmark Runner** "
        "page (either sweep tab), or `python -m bench.orchestrator` / `python -m bench.streaming_runner` "
        "from the CLI, then come back and refresh."
    )
    st.stop()

entry_by_key = {e["key"]: e for e in run_entries}
options = [e["key"] for e in run_entries]
default_index = options.index(default_key) if default_key in options else 0

selected_key = st.selectbox(
    "Data source",
    options=options,
    index=default_index,
    format_func=lambda k: entry_by_key[k]["label"],
    help=(
        "Every concurrency-sweep and streaming-sweep run ever collected, newest first. "
        "'All ... runs combined' aggregates everything of that one type -- the two experiment "
        "types are never combined together, since RTT and time-to-first-token aren't the same "
        "metric. Defaults to whichever type's most recent run is newest."
    ),
)
selected = entry_by_key[selected_key]
mode = selected["type"]  # "concurrency" | "streaming"
run_id = selected["run_id"]  # None == the "all runs combined" pseudo-entry for this type

# ---------------------------------------------------------------------------
# Load the selected run's data. Both branches populate the same handful of
# names (`ok`/`n_total`/`n_ok`/`n_errors` etc. below) so the panels that
# follow can stay mode-aware without duplicating the surrounding page.
# ---------------------------------------------------------------------------
if mode == "concurrency":
    trimmed, summary = dl.get_trimmed_and_summary(warmup_fraction=0.05, run_id=run_id)
    if trimmed is None:
        st.warning("No data in the selected run after warm-up trimming.")
        st.stop()
    ok = trimmed[trimmed["error"].isna() | (trimmed["error"] == "")]
    n_total, n_ok = len(trimmed), len(ok)
    n_errors = n_total - n_ok
    st.caption(
        "The first 5% of requests in each (config, concurrency, repetition) cell are discarded as "
        "connection-pool/JIT warm-up before any statistics below are computed, matching "
        "`analysis/aggregate.py`."
    )
else:
    streaming_df = dl.load_streaming_df(run_id=run_id)
    if streaming_df is None or streaming_df.empty:
        st.warning("No data in the selected streaming run.")
        st.stop()
    streaming_ok = streaming_df[streaming_df["error"].isna() | (streaming_df["error"] == "")]
    n_total, n_ok = len(streaming_df), len(streaming_ok)
    n_errors = n_total - n_ok
    stream_summary = streaming_analysis.summarize(streaming_df)
    stream_configs_present = [c for c in dl.CONFIG_ORDER if c in stream_summary["config"].unique()]
    st.caption(
        "From `bench.streaming_runner` (SSE token streaming). Compares the three signing "
        "strategies (crypto/streaming.py) on time-to-first-token and signature-byte overhead; "
        "there is no unprotected `control` leg in this sweep, so any comparison below is between "
        "the three protected configurations only."
    )

# ---------------------------------------------------------------------------
# Panel: top-line metrics -- same four-tile layout both modes.
# ---------------------------------------------------------------------------
st.divider()
m1, m2, m3, m4 = st.columns(4)
if mode == "concurrency":
    m1.metric("Total requests (post warm-up trim)", f"{n_total:,}")
    m2.metric("Successful", f"{n_ok:,}")
    m3.metric("Errors", f"{n_errors:,}", delta=f"{n_errors / n_total:.1%}" if n_total else None,
              delta_color="inverse")
    m4.metric("Configurations present", trimmed["config"].nunique())
else:
    verified_rate = (
        streaming_ok["stream_fully_verified"].astype(bool).mean() if n_ok else None
    )
    m1.metric("Streaming transactions", f"{n_total:,}")
    m2.metric("Errors", f"{n_errors:,}", delta=f"{n_errors / n_total:.1%}" if n_total else None,
              delta_color="inverse")
    m3.metric("End-to-end verified", f"{verified_rate:.1%}" if verified_rate is not None else "—")
    m4.metric("Configurations present", streaming_df["config"].nunique())

# ---------------------------------------------------------------------------
# Panel: Latency vs. scale -- line chart, log-x where the x-range warrants
# it. Concurrency sweep: RTT vs. concurrency (RQ1), one line per config.
# Streaming: TTFT/total duration vs. response length, one line per strategy
# for a chosen configuration -- the strategy dimension is what this sweep
# adds that the concurrency sweep doesn't have.
# ---------------------------------------------------------------------------
st.divider()

if mode == "concurrency":
    st.subheader("Latency vs. Scale — RTT vs. Concurrency (RQ1)")
    fig1 = go.Figure()
    latency_chart_series = {}
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
        latency_chart_series[config] = {"concurrency": x, "median_rtt_ms": median, "p95_rtt_ms": p95}
    fig1.update_layout(xaxis_type="log", xaxis_title="Concurrency (log scale)", yaxis_title="RTT (ms)",
                        height=450, legend=dict(orientation="h", yanchor="bottom", y=-0.4))
    st.plotly_chart(fig1, width='stretch')
    chart_explainer.render_explain_button(
        chart_key=f"latency_vs_scale:{selected_key}",
        chart_title="Latency vs. Scale — RTT vs. Concurrency (RQ1)",
        chart_data={"x_axis": "concurrency", "y_axis": "RTT (ms)", "series_by_config": latency_chart_series},
    )
else:
    st.subheader("Latency vs. Scale — TTFT & Total Duration vs. Response Length")

    stream_ctrl1, stream_ctrl2 = st.columns(2)
    with stream_ctrl1:
        sel_stream_config = st.selectbox(
            "Configuration", stream_configs_present, format_func=lambda c: dl.CONFIG_LABELS.get(c, c),
            key="stream_config_picker",
        )
    available_chunk_sizes = sorted(stream_summary["chunk_size_tokens"].unique())
    with stream_ctrl2:
        sel_chunk_size = st.select_slider("Chunk size (tokens)", options=available_chunk_sizes,
                                           value=available_chunk_sizes[0], key="stream_chunk_size")

    available_max_tokens = sorted(stream_summary["max_tokens"].unique())
    scale_sub = stream_summary[
        (stream_summary["config"] == sel_stream_config) & (stream_summary["chunk_size_tokens"] == sel_chunk_size)
    ]
    if scale_sub.empty:
        st.info("No streaming rows for this configuration / chunk size.")
    else:
        fig1 = go.Figure()
        latency_chart_series = {}
        for strategy in STRATEGY_ORDER:
            strat_sub = scale_sub[scale_sub["strategy"] == strategy].sort_values("max_tokens")
            if strat_sub.empty:
                continue
            color = STRATEGY_COLORS[strategy]
            fig1.add_trace(go.Scatter(x=strat_sub["max_tokens"], y=strat_sub["ttft_ms_mean"], mode="lines+markers",
                                       name=f"{strategy} (TTFT)", line=dict(color=color)))
            fig1.add_trace(go.Scatter(x=strat_sub["max_tokens"], y=strat_sub["total_ms_mean"], mode="lines+markers",
                                       name=f"{strategy} (total duration)", line=dict(color=color, dash="dash"),
                                       opacity=0.6))
            latency_chart_series[strategy] = {
                "max_tokens": strat_sub["max_tokens"].tolist(),
                "ttft_ms_mean": strat_sub["ttft_ms_mean"].round(1).tolist(),
                "total_ms_mean": strat_sub["total_ms_mean"].round(1).tolist(),
            }
        log_x = len(available_max_tokens) > 1 and max(available_max_tokens) / max(min(available_max_tokens), 1) >= 10
        fig1.update_layout(
            xaxis_type="log" if log_x else "linear",
            xaxis_title=f"Response length (max tokens{', log scale' if log_x else ''})",
            yaxis_title="Time (ms)", height=450,
            legend=dict(orientation="h", yanchor="bottom", y=-0.4),
        )
        st.plotly_chart(fig1, width='stretch')
        chart_explainer.render_explain_button(
            chart_key=f"latency_vs_scale:{selected_key}:{sel_stream_config}:{sel_chunk_size}",
            chart_title="Latency vs. Scale — TTFT & Total Duration vs. Response Length",
            chart_data={
                "configuration": sel_stream_config, "chunk_size_tokens": sel_chunk_size,
                "x_axis": "max_tokens (response length)", "y_axis": "Time (ms)",
                "series_by_strategy": latency_chart_series,
            },
            caveats=["No unprotected `control` leg exists in the streaming sweep."],
        )

# ---------------------------------------------------------------------------
# Panel: Where the overhead comes from -- grouped bar chart. Concurrency
# sweep: protocol-phase decomposition at a chosen concurrency. Streaming:
# per-chunk signing overhead by strategy at the chosen (response length,
# chunk size) -- same chart family, categories swap from protocol-phase to
# signing-strategy.
# ---------------------------------------------------------------------------
st.divider()
st.subheader("Where the Overhead Comes From")

if mode == "concurrency":
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
        overhead_chart_data = {}
        for metric, label in metrics:
            if metric not in sub.columns:
                continue
            vals = [sub[sub["config"] == c][metric].median() for c in protected_configs]
            fig2.add_trace(go.Bar(name=label, x=[dl.CONFIG_LABELS[c] for c in protected_configs], y=vals))
            overhead_chart_data[label] = dict(zip(protected_configs, [round(v, 3) for v in vals]))
        fig2.update_layout(barmode="group", yaxis_title="Median time (ms)", height=400,
                            title=f"Overhead decomposition at concurrency={sel_concurrency}")
        st.plotly_chart(fig2, width='stretch')
        chart_explainer.render_explain_button(
            chart_key=f"overhead:{selected_key}:{sel_concurrency}",
            chart_title=f"Where the Overhead Comes From — decomposition at concurrency={sel_concurrency}",
            chart_data={
                "concurrency": sel_concurrency, "y_axis": "Median time (ms)",
                "median_ms_by_phase_and_config": overhead_chart_data,
            },
        )
    else:
        st.info("No protected-configuration data at this concurrency level yet.")
else:
    sel_max_tokens = st.select_slider("Response length (max tokens)", options=available_max_tokens,
                                       value=available_max_tokens[-1], key="stream_max_tokens_overhead")
    slice_df = stream_summary[
        (stream_summary["max_tokens"] == sel_max_tokens) & (stream_summary["chunk_size_tokens"] == sel_chunk_size)
    ]
    if slice_df.empty or not stream_configs_present:
        st.info("No streaming rows at this response length / chunk size combination.")
    else:
        fig2 = go.Figure()
        overhead_chart_data = {}
        for strategy in STRATEGY_ORDER:
            strat_sub = slice_df[slice_df["strategy"] == strategy].set_index("config").reindex(stream_configs_present)
            # buffer_and_sign never emits "chunk" events client-side (only one
            # "final_buffered" event for the whole response), so n_chunks_mean is
            # always 0 for it -- dividing by that gave inf/NaN, which Plotly quietly
            # drops, making its bar vanish from the chart entirely. buffer_and_sign
            # genuinely performs exactly one signing operation covering the whole
            # response, so treating it as "1 chunk" for this division is the correct
            # semantics (its one-shot signing cost), not a fudge to avoid the crash.
            chunk_divisor = strat_sub["n_chunks_mean"].replace(0, 1)
            per_chunk_signing_ms = strat_sub["total_signing_ms_mean"] / chunk_divisor
            fig2.add_trace(go.Bar(name=strategy, x=[dl.CONFIG_LABELS[c] for c in stream_configs_present],
                                   y=per_chunk_signing_ms, marker_color=STRATEGY_COLORS[strategy]))
            overhead_chart_data[strategy] = dict(zip(stream_configs_present, per_chunk_signing_ms.round(4).tolist()))
        fig2.update_layout(
            barmode="group", yaxis_title="Median signing time per delivery unit (ms)", height=400,
            title=f"Signing overhead by strategy at {sel_max_tokens} max tokens, chunk={sel_chunk_size}",
        )
        st.plotly_chart(fig2, width='stretch')
        st.caption(
            "'Per delivery unit' = per chunk for `per_chunk`/`hash_chain`, and the single one-shot "
            "signature over the whole response for `buffer_and_sign` (it has no intermediate chunks)."
        )
        chart_explainer.render_explain_button(
            chart_key=f"overhead:{selected_key}:{sel_max_tokens}:{sel_chunk_size}",
            chart_title=f"Where the Overhead Comes From — signing overhead by strategy at "
                        f"{sel_max_tokens} max tokens, chunk={sel_chunk_size}",
            chart_data={
                "max_tokens": sel_max_tokens, "chunk_size_tokens": sel_chunk_size,
                "y_axis": "Median signing time per delivery unit (ms)",
                "signing_ms_by_strategy_and_config": overhead_chart_data,
            },
            caveats=[
                "'Per delivery unit' means per chunk for per_chunk/hash_chain, and the single "
                "one-shot signature over the whole response for buffer_and_sign (no intermediate "
                "chunks) -- these are not directly on the same physical unit, only comparable as "
                "'signing cost per thing delivered to the client'.",
            ],
        )

# ---------------------------------------------------------------------------
# Panel: Bytes per request / transaction -- stacked bar chart. Concurrency
# sweep: key-establishment blob + signature bytes genuinely sum to one
# request's total, so they stack. Streaming only reports one wire-bytes
# component (signature bytes) -- there's no second component to stack, and
# the three strategies are alternatives for the same transaction rather than
# additive parts, so they're shown grouped (one bar per strategy) rather
# than summed into a misleading combined height.
# ---------------------------------------------------------------------------
st.divider()
st.subheader("Wire Bytes per Request / Transaction (RQ3)")

if mode == "concurrency":
    if protected_configs:
        kex_bytes = [ok[ok["config"] == c]["kex_blob_bytes"].dropna().median() for c in protected_configs]
        sig_bytes = [ok[ok["config"] == c]["signature_bytes"].dropna().median() for c in protected_configs]
        fig3 = go.Figure()
        fig3.add_trace(go.Bar(name="Key-establishment blob", x=[dl.CONFIG_LABELS[c] for c in protected_configs], y=kex_bytes))
        fig3.add_trace(go.Bar(name="Signature", x=[dl.CONFIG_LABELS[c] for c in protected_configs], y=sig_bytes))
        fig3.update_layout(barmode="stack", yaxis_title="Bytes per request", height=350)
        st.plotly_chart(fig3, width='stretch')
        chart_explainer.render_explain_button(
            chart_key=f"bytes:{selected_key}",
            chart_title="Wire Bytes per Request (RQ3)",
            chart_data={
                "y_axis": "Bytes per request (stacked: key-establishment blob + signature)",
                "kex_blob_bytes_by_config": dict(zip(protected_configs, kex_bytes)),
                "signature_bytes_by_config": dict(zip(protected_configs, sig_bytes)),
            },
        )
    else:
        st.info("No protected-configuration byte data yet.")
else:
    if slice_df.empty or not stream_configs_present:
        st.info("No streaming rows at this response length / chunk size combination.")
    else:
        st.caption(
            "Streaming reports only one wire-bytes component (total signature bytes) per "
            "transaction, unlike the concurrency sweep's two additive components above -- so "
            "there's nothing to stack, and the three strategies are alternative choices for the "
            "same transaction rather than parts of one total, so they're shown side by side."
        )
        fig3 = go.Figure()
        bytes_chart_data = {}
        for strategy in STRATEGY_ORDER:
            strat_sub = slice_df[slice_df["strategy"] == strategy].set_index("config").reindex(stream_configs_present)
            fig3.add_trace(go.Bar(name=strategy, x=[dl.CONFIG_LABELS[c] for c in stream_configs_present],
                                   y=strat_sub["total_signature_bytes_mean"], marker_color=STRATEGY_COLORS[strategy]))
            bytes_chart_data[strategy] = dict(
                zip(stream_configs_present, strat_sub["total_signature_bytes_mean"].round(0).tolist())
            )
        fig3.update_layout(barmode="group", yaxis_title="Total signature bytes (log scale)", yaxis_type="log",
                            height=350,
                            title=f"Signature overhead at {sel_max_tokens} max tokens, chunk={sel_chunk_size}")
        st.plotly_chart(fig3, width='stretch')
        chart_explainer.render_explain_button(
            chart_key=f"bytes:{selected_key}:{sel_max_tokens}:{sel_chunk_size}",
            chart_title=f"Wire Bytes per Transaction (RQ3) — signature overhead at "
                        f"{sel_max_tokens} max tokens, chunk={sel_chunk_size}",
            chart_data={
                "max_tokens": sel_max_tokens, "chunk_size_tokens": sel_chunk_size,
                "y_axis": "Total signature bytes (log scale)",
                "total_signature_bytes_by_strategy_and_config": bytes_chart_data,
            },
            caveats=[
                "Streaming reports only one wire-bytes component (signature bytes); shown grouped, "
                "not stacked, since the three strategies are alternatives for the same transaction, "
                "not additive parts of one total.",
            ],
        )

# ---------------------------------------------------------------------------
# Panel: Server resource usage -- combo chart (CPU% bars + RSS line). Same
# code path both modes: bench.orchestrator samples per (config, concurrency,
# repetition) cell, bench.streaming_runner samples per streaming transaction
# (config, strategy, max_tokens, chunk_size, repetition) -- both write into
# results/sweep_summaries/*.json, and dl.load_resource_summaries() picks out
# just this mode's rows. Runs collected before a sweep type wired up
# ResourceSampler (every streaming run before this feature was added) simply
# have no data -- the info message below, not a fabricated chart.
# ---------------------------------------------------------------------------
st.divider()
st.subheader("Server Resource Usage")
st.caption(
    "Server-process CPU% and RSS sampled every 0.25s during each cell "
    "(crypto.instrumentation.ResourceSampler), attributed to the config whose server "
    "was running at the time -- not available for cells run before this was added, "
    "or for cells too short to catch a sample."
)

resource_df = dl.load_resource_summaries(mode, run_id=run_id)
resource_df = resource_df[resource_df["cpu_percent_mean"].notna()] if not resource_df.empty else resource_df

if resource_df.empty:
    st.info(
        "No resource-usage data for this selection -- either it predates resource sampling "
        f"for {'the concurrency sweep' if mode == 'concurrency' else 'streaming runs'}, "
        "or every cell was too short to catch a 0.25s sample."
    )
else:
    cpu_by_config = resource_df.groupby("config")["cpu_percent_mean"].mean()
    rss_by_config = resource_df.groupby("config")["rss_mb_mean"].mean()
    configs_present = [c for c in ["control", "classical", "hybrid", "full-pqc"] if c in cpu_by_config.index]
    fig_res = make_subplots(specs=[[{"secondary_y": True}]])
    fig_res.add_trace(go.Bar(name="Mean server CPU %", x=configs_present,
                              y=[cpu_by_config[c] for c in configs_present], marker_color=CONFIG_COLORS["classical"]),
                       secondary_y=False)
    fig_res.add_trace(go.Scatter(name="Mean server RSS (MB)", x=configs_present,
                                  y=[rss_by_config[c] for c in configs_present],
                                  mode="markers+lines", marker=dict(size=10, color=CONFIG_COLORS["full_pqc"])),
                       secondary_y=True)
    fig_res.update_yaxes(title_text="CPU %", secondary_y=False)
    fig_res.update_yaxes(title_text="RSS (MB)", secondary_y=True)
    fig_res.update_layout(height=350)
    st.plotly_chart(fig_res, width='stretch')
    chart_explainer.render_explain_button(
        chart_key=f"resource:{selected_key}",
        chart_title="Server Resource Usage — mean CPU% / RSS per configuration",
        chart_data={
            "mean_cpu_percent_by_config": {c: round(cpu_by_config[c], 2) for c in configs_present},
            "mean_rss_mb_by_config": {c: round(rss_by_config[c], 2) for c in configs_present},
            "n_cells_sampled": int(len(resource_df)),
        },
        caveats=[f"Sampled from a {'concurrency' if mode == 'concurrency' else 'streaming'} sweep run "
                 "on a single, possibly resource-constrained host -- absolute numbers are "
                 "hardware-dependent (see docs/DESIGN.md's Known Limitations)."],
    )

# ---------------------------------------------------------------------------
# Panel: Aggregate stats table + significance -- plain dataframe, same style
# both modes.
# ---------------------------------------------------------------------------
st.divider()
st.subheader("Aggregate Statistics")

if mode == "concurrency":
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
        chart_explainer.render_explain_button(
            chart_key=f"significance:{selected_key}",
            chart_title="Mann-Whitney U Test vs. Control (RTT)",
            chart_data={"baseline": "control", "rows": json.loads(sig.to_json(orient="records"))},
        )
else:
    st.caption("Per (config, strategy, response length, chunk size) cell -- the streaming equivalent "
               "of the concurrency sweep's per-(config, concurrency) table above.")
    st.dataframe(stream_summary, width='stretch')
    sig = dl.get_streaming_significance(streaming_df, metric="ttft_ms")
    if sig is None or sig.empty:
        # baseline_config always resolves to "classical" here regardless of whether this
        # call produced any rows -- streaming_df never has a "control" config at all (see
        # analysis.aggregate.resolve_baseline_config), so this heading is never wrong, even
        # though sig carries no "baseline_config" column to read it back from when empty.
        st.subheader("Mann-Whitney U Test vs. Classical (TTFT)")
        st.info(
            "Need at least a 'classical' configuration (the streaming sweep's nearest baseline -- "
            "see the plain-language explainer above) and one other protected configuration, with "
            "2+ repetitions each, at the same (strategy, response length, chunk size) to compute "
            "significance."
        )
    else:
        baseline_label = sig["baseline_config"].iloc[0].capitalize()
        st.subheader(f"Mann-Whitney U Test vs. {baseline_label} (TTFT)")
        st.caption(
            "The streaming sweep has no unprotected `control` leg, so this is relative to "
            f"**{baseline_label}**, not Control — not the same baseline as the concurrency sweep's "
            "table above; see the explainer at the top of this page."
        )
        st.dataframe(
            sig.style.format({
                "median_control": "{:.2f}", "median_treatment": "{:.2f}",
                "overhead_pct_vs_control": "{:.1f}%", "p_value": "{:.4g}",
            }),
            width='stretch',
        )
        chart_explainer.render_explain_button(
            chart_key=f"significance:{selected_key}",
            chart_title=f"Mann-Whitney U Test vs. {baseline_label} (TTFT)",
            chart_data={"baseline": baseline_label, "rows": json.loads(sig.to_json(orient="records"))},
            caveats=["The streaming sweep has no unprotected `control` leg, so this is relative to "
                     f"{baseline_label}, not the concurrency sweep's control baseline."],
        )

    with st.expander("Strategy comparison at a chosen (configuration, response length, chunk size)"):
        comparison = streaming_analysis.strategy_comparison_at(
            streaming_df, sel_stream_config, sel_max_tokens, sel_chunk_size
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

# ---------------------------------------------------------------------------
# Cryptographic validation now lives on its own page (pages/5_🔬_Cryptographic_
# Validation.py) -- it validates the measurement instrument itself (NIST KAT
# vectors, the streaming signature-cost model), independent of any run
# selector here, so it doesn't belong inside a run-scoped page.
# ---------------------------------------------------------------------------
st.divider()
st.info("🔬 Cryptographic validation (NIST KAT vectors, streaming signature-cost model) has moved to its own "
        "page — see **🔬 Cryptographic Validation** in the sidebar.")

# ---------------------------------------------------------------------------
# Interactive trade-off matrix -- same panel both modes. Concurrency sweep:
# config x concurrency, overhead relative to `control` (present in every
# concurrency-sweep run), security_score = the plain categorical
# SECURITY_SCORES mapping. Streaming: config x response length, overhead
# relative to `classical` (the streaming sweep's nearest real baseline --
# there's no unprotected control leg to measure against), and -- since
# signing strategy is a real, measured security-relevant choice for a
# streaming run that the concurrency sweep has no equivalent of --
# security_score is a per-strategy BLEND of that same categorical mapping
# with the measured sequence-integrity exposure window
# (analysis.tradeoff_matrix.streaming_security_score), for whichever
# strategy is selected below. The baseline is never assumed silently: it's
# read back from build_custom_tradeoff's "baseline_config" column and
# surfaced in the heading/caption/conclusion so the two halves of this page
# are never visually confused for the same number.
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

if mode == "concurrency":
    scale_col, metric_col = "concurrency", "rtt_ms"
    matrix = dl.build_custom_tradeoff(trimmed, w_sec, w_perf, scale_col=scale_col, metric_col=metric_col)
    scale_axis_label = "Concurrency"
    sel_scale_val = sel_concurrency
    tradeoff_strategy = None
else:
    scale_col, metric_col = "max_tokens", "ttft_ms"
    tc1, tc2 = st.columns(2)
    with tc1:
        tradeoff_strategy = st.selectbox(
            "Signing strategy (for the security score's exposure-window term)",
            [s for s in STRATEGY_ORDER if s in streaming_df["strategy"].unique()],
            key="tradeoff_strategy",
        )
    with tc2:
        exposure_share = st.slider(
            "Exposure-window share of the security score", 0.0, 1.0, DEFAULT_EXPOSURE_SHARE, 0.05,
            key="tradeoff_exposure_share",
            help="0 = plain quantum-resistance category only (same score every strategy shares); "
                 "1 = entirely the measured sequence-integrity exposure window for this strategy. "
                 "Blended into security_score, not a separate weighted term -- see docs/DESIGN.md.",
        )
    streaming_mitm_summaries = dl.load_streaming_mitm_summaries()
    streaming_scores = {
        c: streaming_security_score(c, tradeoff_strategy, streaming_mitm_summaries, exposure_share=exposure_share)
        for c in dl.CONFIG_ORDER if c != "control"
    }
    streaming_scores = {c: s for c, s in streaming_scores.items() if s is not None}
    strategy_df = streaming_df[streaming_df["strategy"] == tradeoff_strategy]
    matrix = dl.build_custom_tradeoff(
        strategy_df, w_sec, w_perf, scale_col=scale_col, metric_col=metric_col, security_scores=streaming_scores
    )
    scale_axis_label = "Response length (max tokens)"
    sel_scale_val = sel_max_tokens
    if not streaming_scores:
        st.info(
            f"No sequence-attack data yet for strategy `{tradeoff_strategy}` — run the 🌊 Streaming "
            "Sequence Attack tab on the Threat Scenarios page for at least one configuration to "
            "populate the exposure-window term."
        )

if matrix.empty:
    st.info(
        "Need at least one protected configuration and a baseline "
        f"({'control' if mode == 'concurrency' else 'classical'}) at a shared "
        f"{'concurrency' if mode == 'concurrency' else 'response length'} level."
    )
else:
    baseline_config = matrix["baseline_config"].iloc[0]
    baseline_label = baseline_config.capitalize()
    if mode == "streaming":
        st.caption(
            f"Overhead relative to **{baseline_label}** (no unprotected control leg in the "
            "streaming sweep) — not the same baseline as the concurrency sweep's heatmap. "
            f"security_score blends the categorical mapping above with `{tradeoff_strategy}`'s measured "
            f"sequence-integrity exposure window (exposure share = {exposure_share:.2f}) — see the 🌊 "
            "Streaming Sequence Attack tab on the Threat Scenarios page for the underlying data."
        )

    pivot = matrix.pivot(index="config", columns=scale_col, values="composite_score")
    pivot = pivot.reindex([c for c in ["classical", "hybrid", "full_pqc"] if c in pivot.index])

    fig6 = px.imshow(
        pivot.values, x=[str(c) for c in pivot.columns], y=[dl.CONFIG_LABELS[c] for c in pivot.index],
        color_continuous_scale="RdYlGn", text_auto=".2f", aspect="auto",
        labels=dict(x=scale_axis_label, y="Configuration", color="Composite score"),
    )
    fig6.update_layout(height=350)
    st.plotly_chart(fig6, width='stretch')
    tradeoff_chart_key = f"tradeoff:{selected_key}:{w_sec}"
    tradeoff_caveats = [f"Overhead is relative to {baseline_label}."]
    if mode == "streaming":
        tradeoff_chart_key += f":{tradeoff_strategy}:{exposure_share}"
        tradeoff_caveats.append(
            f"security_score blends the categorical quantum-resistance mapping with `{tradeoff_strategy}`'s "
            f"measured sequence-integrity exposure window (exposure share = {exposure_share:.2f})."
        )
    chart_explainer.render_explain_button(
        chart_key=tradeoff_chart_key,
        chart_title="Security / Performance Trade-off Matrix (Layer 6)",
        chart_data={
            "w_sec": w_sec, "w_perf": w_perf, "baseline_config": baseline_config,
            "scale_axis": scale_axis_label,
            "rows": json.loads(matrix.to_json(orient="records")),
        },
        caveats=tradeoff_caveats,
    )

    best_per_scale = matrix.loc[matrix.groupby(scale_col)["composite_score"].idxmax()]
    st.markdown(f"**Recommended configuration per {scale_axis_label.lower()} level, at this weighting:**")
    st.dataframe(
        best_per_scale[[scale_col, "config", "composite_score", "normalized_latency_overhead"]]
        .assign(config=lambda d: d["config"].map(dl.CONFIG_LABELS))
        .style.format({"composite_score": "{:.3f}", "normalized_latency_overhead": "{:.1%}"}),
        width='stretch',
    )

    # The plain-language conclusion this whole page is for: one sentence a
    # non-crypto-expert reviewer can act on without reading the heatmap.
    conclusion_scale_val = sel_scale_val if sel_scale_val in matrix[scale_col].values else None
    conclusion_slice = (
        matrix[matrix[scale_col] == conclusion_scale_val] if conclusion_scale_val is not None else matrix
    )
    if not conclusion_slice.empty:
        best_row = conclusion_slice.loc[conclusion_slice["composite_score"].idxmax()]
        scale_note = (
            f"and {scale_col}={int(best_row[scale_col])}" if conclusion_scale_val is not None
            else f"(best across all {scale_col} levels combined, shown at {scale_col}={int(best_row[scale_col])})"
        )
        baseline_phrase = "vs. control" if baseline_config == "control" else f"relative to the {baseline_label} baseline"
        strategy_phrase = f", with `{tradeoff_strategy}` signing," if mode == "streaming" else ""
        conclusion = (
            f"**At this weighting (w_sec={w_sec:.2f}){strategy_phrase} {scale_note}, "
            f"{dl.CONFIG_LABELS[best_row['config']]} gives the best balance of quantum resistance "
            f"and latency overhead** (composite score {best_row['composite_score']:.3f}, "
            f"{best_row['normalized_latency_overhead']:.1%} latency overhead {baseline_phrase})."
        )

        # Don't let the recommendation hide the exposure-window trade-off the new
        # term exists to surface: if the winning config would score differently
        # under the other attackable strategy, say so explicitly.
        if mode == "streaming":
            other_strategies = [s for s in ["per_chunk", "hash_chain"] if s in streaming_df["strategy"].unique()
                                 and s != tradeoff_strategy]
            if other_strategies:
                other_strategy = other_strategies[0]
                this_exposure = streaming_security_score(
                    best_row["config"], tradeoff_strategy, streaming_mitm_summaries, exposure_share=1.0
                )
                other_exposure = streaming_security_score(
                    best_row["config"], other_strategy, streaming_mitm_summaries, exposure_share=1.0
                )
                if this_exposure is not None and other_exposure is not None and this_exposure != other_exposure:
                    direction = "smaller" if other_exposure > this_exposure else "larger"
                    conclusion += (
                        f" Note: `{other_strategy}` would give {dl.CONFIG_LABELS[best_row['config']]} a "
                        f"{direction} sequence-attack exposure window than `{tradeoff_strategy}` does."
                    )
        st.markdown(conclusion)

# ---------------------------------------------------------------------------
# AI summary -- concurrency-sweep runs only for now: it summarizes the RTT /
# overhead-decomposition / trade-off-matrix data computed above, none of
# which exists in that shape for a streaming run. Not run-selector-scoped
# beyond that guard, matching its previous behavior.
# ---------------------------------------------------------------------------
st.divider()
st.subheader("🤖 AI Summary")

from webapp import ai_summary

if mode != "concurrency":
    st.info(
        "AI summary is available when a concurrency-sweep run is selected above — it summarizes "
        "the RTT, overhead-decomposition, and trade-off-matrix data from that panel structure, "
        "which doesn't exist in the same shape for a streaming run."
    )
elif not ai_summary.api_key_present():
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
            resource_df=resource_df if resource_df is not None and not resource_df.empty else None,
        )
        try:
            with st.spinner("Asking Claude..."):
                text = ai_summary.generate_dashboard_summary(context)
            st.markdown(text)
        except Exception as exc:
            st.error(f"AI summary failed: {exc}")
