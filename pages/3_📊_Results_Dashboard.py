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

from webapp import data_loader as dl

st.set_page_config(page_title="PQ-Shield — Results Dashboard", page_icon="📊", layout="wide")
st.title("📊 Results Dashboard")

CONFIG_COLORS = {"control": "#888888", "classical": "#c0392b", "hybrid": "#e67e22", "full_pqc": "#2471a3"}

refresh = st.button("🔄 Refresh data")

trimmed, summary = dl.get_trimmed_and_summary(warmup_fraction=0.05)

if trimmed is None:
    st.warning(
        "No results/raw/*.csv found yet. Run the **Benchmark Runner** page, or "
        "`python -m bench.orchestrator` from the CLI, then come back and refresh."
    )
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
