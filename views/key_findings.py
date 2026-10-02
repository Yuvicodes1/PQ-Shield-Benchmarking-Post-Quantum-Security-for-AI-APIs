import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from webapp import data_loader as dl
from webapp import findings as fd
from webapp import ui
from webapp.colors import CONFIG_COLORS

ui.page_header(
    "Key findings",
    "The paper's results, computed from the paper's own runs (<code>results/paper_runs.json</code>) with the same "
    "code that builds its tables. For a streamed LLM response the post-quantum cost lies in the "
    "<b>signature schedule</b>, not the key exchange.",
    eyebrow="Evidence · paper runs",
)

manifest = dl.load_manifest()
if not manifest:
    ui.empty_state("No paper-run manifest found.", "Run `python -m bench.paper_runs` to reproduce the experiments.")
    st.stop()

t_sched, t_cost, t_attack, t_auth, t_kex, t_decide = st.tabs([
    "Signature schedule", "Signing cost", "Stream integrity", "Handshake authentication",
    "Key establishment", "Decide",
])

# ====================================================================== schedule
with t_sched:
    st.markdown("Sign every chunk and nothing is ever shown unverified — at a price in bytes. Sign once at the "
                "end and the whole response is unverified until it finishes. A hash chain with a checkpoint every "
                "*k* chunks spans the range.")
    c1, c2, c3 = st.columns([1.2, 1, 1])
    with c1:
        k_choice = st.segmented_control("Checkpoint interval k (chunks)", ["1", "2", "5", "10", "20", "∞"],
                                        default="5", key="k_dial")
    with c2:
        n_tokens = st.slider("Response length (tokens)", 50, 1000, 200, step=50)
    with c3:
        chunk = st.slider("Chunk size (tokens)", 1, 20, 5)
    k = None if k_choice in (None, "∞") else int(k_choice)
    n_e, b_e, exp_e = fd.signature_bytes(n_tokens, chunk, k, 71)
    n_m, b_m, exp_m = fd.signature_bytes(n_tokens, chunk, k, 3309)
    ui.kpi_cards([
        {"label": "Signatures per response", "value": f"{n_m}", "sub": f"⌊n/k⌋ + 1 with n = {int(np.ceil(n_tokens / chunk))} chunks"},
        {"label": "ML-DSA-65 bytes", "value": f"{b_m:,} B", "sub": "Full PQC · Hybrid-KEX-PQ", "color": CONFIG_COLORS["full_pqc"]},
        {"label": "ECDSA P-256 bytes", "value": f"{b_e:,} B", "sub": "Classical · Hybrid · Hybrid-KEX", "color": CONFIG_COLORS["hybrid"]},
        {"label": "Max tokens shown unverified", "value": f"{exp_m}", "sub": "exposure before a verified signature covers them"},
    ])

    cdf = fd.streaming(manifest.get("checkpoint"))
    fig = go.Figure()
    ks = [1, 2, 5, 10, 20, None]
    for sig_bytes, cfg, name in ((3309, "full_pqc", "ML-DSA-65 (model)"), (71, "hybrid", "ECDSA (model)")):
        pts = [fd.signature_bytes(n_tokens, chunk, kk, sig_bytes) for kk in ks]
        fig.add_trace(go.Scatter(x=[p[2] for p in pts], y=[p[1] for p in pts], mode="lines", name=name,
                                 line=dict(color=CONFIG_COLORS[cfg], dash="dot", width=2), hoverinfo="skip"))
    if cdf is not None and not cdf.empty:
        hc = cdf[cdf["strategy"] == "hash_chain"].assign(k=lambda d: d["checkpoint_interval"].fillna(0).astype(int))
        cch = int(hc["chunk_size_tokens"].mode()[0])
        for cfg in ("hybrid", "full_pqc", "hybrid_kex_pq"):
            g = hc[hc["config"] == cfg].groupby("k").agg(b=("total_signature_bytes", "median"),
                                                          e=("max_unverified_chunks", "median"),
                                                          lag=("max_verification_lag_ms", "median"))
            if g.empty:
                continue
            fig.add_trace(go.Scatter(
                x=g["e"] * cch, y=g["b"], mode="markers", name=f"{ui.SHORT[cfg]} (measured, 200 tok)",
                marker=dict(size=11, color=CONFIG_COLORS[cfg], line=dict(width=1.5, color="white"),
                            symbol={"hybrid": "triangle-up", "full_pqc": "diamond", "hybrid_kex_pq": "x"}[cfg]),
                text=[f"k={'∞' if kk == 0 else kk}" for kk in g.index],
                customdata=g["lag"], hovertemplate="%{text}<br>%{y:,.0f} B<br>exposure %{x} tokens"
                                                   "<br>max lag %{customdata:,.0f} ms<extra></extra>"))
    sel_b = b_m
    fig.add_trace(go.Scatter(x=[exp_m], y=[sel_b], mode="markers", name="Your setting (ML-DSA-65)",
                             marker=dict(size=18, color="rgba(0,0,0,0)", line=dict(width=2.5, color="#4f46e5"))))
    fig.update_xaxes(type="log", title="Max tokens shown before verification (exposure)")
    fig.update_yaxes(type="log", title="Signature bytes per response")
    ui.chart(ui.style_fig(fig, 440))
    st.caption("Dotted lines: the analytic model (⌊n/k⌋ + 1 signatures). Markers: measured on Llama-3.2-3B, "
               "200-token responses, 5-token chunks — byte counts match the model exactly in all 18 cells.")

# ====================================================================== signing cost
with t_cost:
    st.markdown("Signature **bytes** match the model exactly; signature **time** inside a stream does not match a "
                "back-to-back microbenchmark. Between chunks the processor clocks down, so each signature runs "
                "on a slow core. CPU time rises with wall time, so this is work, not waiting.")
    cc = dl.load_contention_check()
    if cc is None:
        ui.empty_state("No signing-cost diagnostic yet.", "Run `python -m validation.contention_check`.")
    else:
        phases = [("idle", "Back-to-back, idle"), ("llama_generating", "Back-to-back, during generation"),
                  ("busy_spaced", "Every 125 ms, core kept busy"), ("ecores", "Back-to-back, efficiency cores"),
                  ("llama_spaced", "Every 125 ms, during generation"), ("idle_spaced", "Every 125 ms, idle")]
        op = st.segmented_control("Operation", ["sign", "verify"], default="sign", key="cost_op") or "sign"
        fig = go.Figure()
        for cfg, name in (("hybrid", "ECDSA P-256"), ("full_pqc", "ML-DSA-65")):
            vals = [cc[(cc["phase"] == ph) & (cc["config"] == cfg)][f"{op}_cpu_ms"].median() * 1000 for ph, _ in phases]
            fig.add_trace(go.Bar(y=[n for _, n in phases], x=vals, name=name, orientation="h",
                                 marker_color=CONFIG_COLORS[cfg], text=[f"{v:,.0f} µs" for v in vals],
                                 textposition="outside", cliponaxis=False))
        fig.update_xaxes(title=f"{op.capitalize()} cost per call, thread-CPU µs (median)")
        fig.update_layout(barmode="group", yaxis=dict(autorange="reversed"))
        ui.chart(ui.style_fig(fig, 420))
        sdf = fd.streaming(manifest.get("streaming"))
        cdf = fd.streaming(manifest.get("checkpoint"))
        frames = [d for d in (sdf, cdf) if d is not None and "total_signing_cpu_ms" in d]
        if frames:
            allc = pd.concat(frames)
            allc = allc[allc["n_signatures"] > 0]
            for cfg_set, name in ((["classical", "classical_ecdhe", "hybrid", "hybrid_kex"], "ECDSA"),
                                  (["full_pqc", "hybrid_kex_pq"], "ML-DSA-65")):
                v = allc[allc["config"].isin(cfg_set)]
                col = "total_signing_cpu_ms" if op == "sign" else "total_verify_cpu_ms"
                per = (v[col] / v["n_signatures"] * 1000).groupby(
                    [v["config"], v["strategy"], v["max_tokens"], v["checkpoint_interval"].fillna(0)]).median()
                st.markdown(f"In real streams, **{name}** {op} cost {per.min():,.0f}–{per.max():,.0f} µs per "
                            f"signature across {len(per)} cells — inside the band above.")
        st.caption("At most ~23 ms of signing per 200-token stream that takes 5–6 s to generate, so the time is "
                   "small in absolute terms; it is bounded, not predicted, by the microbenchmark.")

# ====================================================================== stream integrity
with t_attack:
    camp = fd.campaign_frame()
    if camp is None:
        ui.empty_state("No attack-campaign results yet.", "Run `python -m threats.streaming_attack_campaign`.")
    else:
        n_streams = int(camp.attrs.get("pool") or 10) * camp["config"].nunique()
        att = camp[camp["attack"] != "benign"]
        ben = camp[camp["attack"] == "benign"]
        v2 = att[att["attack"] == "checkpoint_strip_v2client"]
        rest = att[att["attack"] != "checkpoint_strip_v2client"]
        ui.kpi_cards([
            {"label": "Attacked trials detected", "value": f"{int(rest['detected'].sum()):,} / {int(rest['n'].sum()):,}",
             "sub": f"{n_streams} distinct streams per cell → 95% lower bound 94.0% of streams", "color": "#16a085"},
            {"label": "False rejections", "value": f"{int(ben['detected'].sum())} / {int(ben['n'].sum())}",
             "sub": "genuine streams in the campaign (0/750 incl. the sweeps)"},
            {"label": "Checkpoint stripping vs. old client", "value": f"{int(v2['detected'].sum())} / {int(v2['n'].sum()):,}",
             "sub": "detected without schedule enforcement — fixed by enforcing the requested k", "color": "#c0392b"},
        ])
        cells = [("per_chunk", 0, "Per-chunk"), ("hash_chain", 0, "Chain k=∞"), ("hash_chain", 10, "k=10"),
                 ("hash_chain", 5, "k=5"), ("hash_chain", 2, "k=2")]
        names = {"drop": "Drop a chunk", "reorder": "Reorder two chunks", "duplicate": "Duplicate a chunk",
                 "replay": "Replay a foreign chunk", "session_replay": "Replay a whole session",
                 "truncate": "Truncate", "checkpoint_strip": "Strip checkpoints",
                 "checkpoint_strip_v2client": "Strip checkpoints (old client)", "checkpoint_move": "Move a checkpoint",
                 "drop_before_ckpt": "Drop before checkpoint", "drop_after_ckpt": "Drop after checkpoint",
                 "reorder_across": "Reorder across checkpoint"}
        metric = st.segmented_control(
            "Show", ["Unverified chunks shown at rejection", "Caught before the stream ended (%)", "Detected (%)"],
            default="Unverified chunks shown at rejection", key="camp_metric") or "Unverified chunks shown at rejection"
        z, txt = [], []
        for a in names:
            row, trow = [], []
            for s, k, _ in cells:
                g = camp[(camp["strategy"] == s) & (camp["k"] == k) & (camp["attack"] == a)]
                if g.empty or g["n"].sum() == 0:
                    row.append(None); trow.append("")
                    continue
                n = g["n"].sum()
                if metric.startswith("Unverified"):
                    v = (g["unverified_at_detection_mean"] * g["n"]).sum() / n
                    trow.append(f"{v:.1f}")
                elif metric.startswith("Caught"):
                    v = 100 * g["mid_stream"].sum() / n
                    trow.append(f"{v:.0f}%")
                else:
                    v = 100 * g["detected"].sum() / n
                    trow.append(f"{v:.0f}%")
                row.append(v)
            z.append(row); txt.append(trow)
        scale = "Reds" if metric.startswith("Unverified") else "Teal"
        fig = go.Figure(go.Heatmap(z=z, x=[c[2] for c in cells], y=list(names.values()), text=txt,
                                   texttemplate="%{text}", colorscale=scale, showscale=False, xgap=3, ygap=3,
                                   hovertemplate="%{y} · %{x}<br>%{text}<extra></extra>"))
        fig.update_yaxes(autorange="reversed")
        ui.chart(ui.style_fig(fig, 470, legend=None))
        st.caption(f"Pooled over {camp['config'].nunique()} configurations, {camp.attrs.get('trials')} trials per "
                   f"configuration and cell on {camp.attrs.get('max_tokens')}-token Llama streams. Detection is not "
                   "prevention: without checkpoints, reordering or truncation is caught only after the text was "
                   "shown. Results were identical across configurations.")

# ====================================================================== handshake auth
with t_auth:
    st.markdown("Post-quantum key exchange protects recorded traffic from a future quantum computer. It does "
                "nothing against an active attacker who swaps in their own keys, unless the client can check whose "
                "keys it received.")
    ks = dl.load_key_substitution()
    if not ks:
        ui.empty_state("No key-substitution results yet.", "Run `python -m threats.key_substitution`.")
    else:
        kdf = pd.DataFrame(ks)
        variants = [("benign", "No attack"), ("substitute", "Substitute keys"),
                    ("substitute_resign", "Substitute + re-sign"), ("relay_tamper", "Relay + bit flip")]
        cols = st.columns(2)
        for col, (mode, title) in zip(cols, (("unauthenticated", "Unauthenticated handshake"),
                                             ("pinned", "Pinned identity key"))):
            with col:
                with st.container(border=True):
                    st.markdown(f"**{title}**")
                    rows = []
                    for v, name in variants:
                        g = kdf[(kdf["mode"] == mode) & (kdf["variant"] == v)]
                        n = int(g["n_valid"].sum())
                        rej = {}
                        for d in g["rejected_at"]:
                            for kk, cnt in (d or {}).items():
                                rej[kk] = rej.get(kk, 0) + cnt
                        rows.append({"Attack": name, "Accepted": int(g["accepted"].sum()),
                                     "Read": int(g["attacker_read_request"].sum()),
                                     "Forged": int(g["forged_response_accepted"].sum()),
                                     "Stopped at": ", ".join(rej) or "—"})
                    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch",
                                 column_config={
                                     "Read": st.column_config.NumberColumn(help="Attacker decrypted the request"),
                                     "Forged": st.column_config.NumberColumn(help="Client accepted an attacker-chosen prediction")})
        st.caption(f"Out of {int(kdf.groupby(['mode', 'variant'])['n_valid'].sum().max()):,} trials per row: "
                   f"{kdf['config'].nunique()} configurations × 300, against a live server. "
                   "Results were identical for post-quantum and classical configurations.")
    entries = tuple((e["config"], e["auth"], e["run_id"]) for e in manifest.get("auth_cost", []))
    if entries:
        with st.spinner("Computing authentication cost…"):
            ac = fd.auth_cost(entries)
        if ac is not None and not ac.empty:
            ui.section("What authentication costs", "One extra signature per handshake; end-to-end difference at "
                       "10 connections with 95% CI (run back to back with the unauthenticated configuration).")
            fig = go.Figure()
            for _, r in ac.iterrows():
                fig.add_trace(go.Scatter(
                    x=[r["diff_ms"]], y=[ui.label(r["config"])], mode="markers",
                    error_x=dict(type="data", symmetric=False, array=[r["hi"] - r["diff_ms"]],
                                 arrayminus=[r["diff_ms"] - r["lo"]], thickness=2),
                    marker=dict(size=12, color=CONFIG_COLORS[r["config"]]), showlegend=False,
                    hovertemplate=f"{ui.SHORT[r['config']]}<br>Δ %{{x:+.2f}} ms<br>verify {r['verify_us']:.0f} µs"
                                  f"<br>+{r['extra_bytes']:,} B<extra></extra>"))
            fig.add_vline(x=0, line_width=1, line_dash="dot", line_color="gray")
            fig.update_xaxes(title="Added end-to-end latency (ms)")
            fig.update_yaxes(autorange="reversed")
            ui.chart(ui.style_fig(fig, 320, legend=None))

# ====================================================================== key establishment
with t_kex:
    st.markdown("Measured against a matched no-crypto control (Control-2RT, same two HTTP requests), the "
                "cryptographic overhead at 10 connections is a few milliseconds. This confirms prior TLS studies.")
    run_ids = tuple(fd.concurrency_run_ids())
    with st.spinner("Computing bootstrap statistics (cached after the first run)…"):
        conc = fd.concurrency(run_ids)
    if conc is None:
        ui.empty_state("No concurrency data for the paper runs.")
    else:
        cmp, stats = conc["cmp"], conc["stats"]
        c10_all = cmp[(cmp["concurrency"] == 10) & (cmp["reference"] == "control_2rt")]
        rsa = c10_all[c10_all["config"] == "classical"]
        c10 = c10_all[c10_all["config"] != "classical"]
        fig = go.Figure()
        for _, r in c10.iterrows():
            fig.add_trace(go.Scatter(
                x=[r["diff_ms"]], y=[ui.label(r["config"])], mode="markers",
                error_x=dict(type="data", symmetric=False, array=[r["ci95_hi"] - r["diff_ms"]],
                             arrayminus=[r["diff_ms"] - r["ci95_lo"]], thickness=2),
                marker=dict(size=12, color=CONFIG_COLORS[r["config"]]), showlegend=False,
                hovertemplate=f"{ui.SHORT[r['config']]}<br>%{{x:+.1f}} ms [{r['ci95_lo']:+.1f}, "
                              f"{r['ci95_hi']:+.1f}]<extra></extra>"))
        fig.add_vline(x=0, line_width=1, line_dash="dot", line_color="gray")
        fig.update_xaxes(title="Cryptographic overhead vs Control-2RT at 10 connections (ms, 95% CI)")
        fig.update_yaxes(autorange="reversed")
        l, r_ = st.columns([1.35, 1])
        with l:
            ui.chart(ui.style_fig(fig, 320, legend=None))
            if not rsa.empty:
                r0 = rsa.iloc[0]
                st.caption(f"Off the scale: Classical-RSA {r0['diff_ms']:+.1f} ms [{r0['ci95_lo']:+.1f}, "
                           f"{r0['ci95_hi']:+.1f}] — a fresh RSA-2048 key pair per handshake.")
        with r_:
            eq = cmp[(cmp["concurrency"] == 10) & (cmp["reference"] == "classical_ecdhe")]
            rows = []
            for _, r in eq.iterrows():
                lo, hi = 100 * r["ci90_lo"] / r["ref_median"], 100 * r["ci90_hi"] / r["ref_median"]
                rows.append({"Configuration": ui.label(r["config"]), "Δ vs X25519": f"{r['diff_pct']:+.1f}%",
                             "90% CI": f"[{lo:+.1f}, {hi:+.1f}]",
                             "Equiv.": "✓" if -5 < lo and hi < 5 else "—"})
            st.markdown("**Equivalent to X25519 within ±5%?** (10 connections)")
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
        st.info("At 100 and 1,000 connections client and server share one CPU: the protected configurations even "
                "come out faster than the no-crypto Control-2RT at 1,000, so the matched-protocol subtraction no "
                "longer isolates cryptography. No verdicts are drawn there.", icon=":material/info:")
        with st.expander("Latency by concurrency, and failed requests"):
            fig = go.Figure()
            for cfg in ui.CONFIG_ORDER:
                s = stats[stats["config"] == cfg].sort_values("concurrency")
                if s.empty:
                    continue
                fig.add_trace(go.Scatter(x=s["concurrency"], y=s["median"], mode="lines+markers", name=ui.SHORT[cfg],
                                         line=dict(color=CONFIG_COLORS[cfg]),
                                         error_y=dict(type="data", symmetric=False, array=s["q75"] - s["median"],
                                                      arrayminus=s["median"] - s["q25"], thickness=1)))
            fig.update_xaxes(type="log", title="Concurrent connections")
            fig.update_yaxes(type="log", title="End-to-end latency (ms, median with IQR)")
            ui.chart(ui.style_fig(fig, 420))
            f = conc["fail"]
            if not f.empty:
                piv = f.pivot_table(index=["concurrency", "config"], columns="stage", values="n", fill_value=0)
                piv = piv.reset_index().assign(config=lambda d: d["config"].map(ui.label))
                st.markdown("**Failed requests** — all connection resets (no timeouts, no HTTP errors); counting "
                            "them at the 30 s timeout changes no comparison.")
                st.dataframe(piv, hide_index=True, width="stretch")

# ====================================================================== decide
with t_decide:
    st.markdown("No weights, no composite score. Pick the properties you need and the workload; the explorer lists "
                "the configurations that qualify and what they cost. Latency is compared at 10 connections only.")
    run_ids = tuple(fd.concurrency_run_ids())
    with st.spinner("Computing…"):
        dom = fd.dominance(run_ids, manifest.get("streaming"))
    q1, q2, q3, q4 = st.columns([1, 1, 1, 1.15])
    need_kexq = q1.toggle("Key exchange resists a quantum computer", value=True,
                          help="Protects recorded traffic against harvest-now-decrypt-later.")
    need_kexh = q2.toggle("Key exchange survives an ML-KEM break", value=False,
                          help="Hedge against a flaw in ML-KEM itself (X25519MLKEM768).")
    need_sigq = q3.toggle("Signatures resist a quantum computer", value=False,
                          help="Quantum-resistant authenticity / long-term non-repudiation.")
    wl = q4.radio("Workload", ["API / hash chain", "Per-chunk stream"], horizontal=True, key="decide_wl")
    workload = "API / hash-chain" if wl.startswith("API") else "Per-chunk streaming"
    if dom is None:
        ui.empty_state("No data for the decision explorer.")
    else:
        ov = dom["overhead"]
        bytes_map = dom["hs_bytes"] if workload.startswith("API") else dom["pc_bytes"]
        rows = []
        for c in dom["present"]:
            ok = ((not need_kexq or ui.KEX_PQ[c]) and (not need_kexh or ui.KEX_HEDGED[c])
                  and (not need_sigq or ui.SIG_PQ[c]))
            r = ov[(ov["config"] == c) & (ov["concurrency"] == 10)] if not ov.empty else ov
            d_by = dom["dominated_by"][workload][c]
            rows.append({
                "Configuration": ui.label(c), "Meets needs": ok,
                "KEX vs CRQC": "✓" if ui.KEX_PQ[c] else "—", "KEX hedged": "✓" if ui.KEX_HEDGED[c] else "—",
                "Sig vs CRQC": "✓" if ui.SIG_PQ[c] else "—",
                "Crypto overhead @10 (ms)": float(r["diff_ms"].iloc[0]) if not r.empty else np.nan,
                "Bytes": float(bytes_map.get(c, np.nan)),
                "Dominated by": ", ".join(ui.CODE[o] for o in d_by) or "—",
            })
        table = pd.DataFrame(rows).sort_values(["Meets needs", "Bytes"], ascending=[False, True])
        best = table[table["Meets needs"]]
        if best.empty:
            st.warning("No configuration has every property you selected.")
        else:
            b = best.iloc[0]
            st.success(f"**{b['Configuration']}** is the cheapest configuration that meets your needs for this workload "
                       f"({b['Bytes']:,.0f} B; {b['Crypto overhead @10 (ms)']:+.1f} ms at 10 connections).",
                       icon=":material/check_circle:")
        st.dataframe(
            table, hide_index=True, width="stretch",
            column_config={
                "Meets needs": st.column_config.CheckboxColumn(),
                "Crypto overhead @10 (ms)": st.column_config.NumberColumn(format="%+.1f"),
                "Bytes": st.column_config.ProgressColumn(
                    format="%,.0f B", min_value=0, max_value=float(table["Bytes"].max() or 1)),
            })
        st.caption("Whatever you pick, authenticate the handshake: without it any configuration falls to key "
                   "substitution. Only Classical-RSA is dominated outright; among the rest, more security costs "
                   "bytes, not latency. Hybrid-KEX-PQ is the least-measured configuration.")
