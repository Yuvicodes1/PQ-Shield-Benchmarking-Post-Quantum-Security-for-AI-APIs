import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from webapp.bootstrap import load_dotenv_if_needed

load_dotenv_if_needed()

import json

import plotly.graph_objects as go
import streamlit as st

from webapp import data_loader as dl
from webapp import demo_transaction, server_manager

st.set_page_config(page_title="PQ-Shield — Threat Scenarios", page_icon="🛡️", layout="wide")
st.title("🛡️ Threat Scenarios")

tab_hndl, tab_mitm, tab_streaming_mitm, tab_streaming_hndl = st.tabs([
    "Harvest-Now-Decrypt-Later (HNDL)", "Man-in-the-Middle (MITM)", "🌊 Streaming Sequence Attack",
    "🌊 Streaming HNDL Exposure",
])

# ---------------------------------------------------------------------------
# HNDL
# ---------------------------------------------------------------------------
with tab_hndl:
    st.markdown(
        "Simulates a passive adversary archiving every cryptographic artifact "
        "(key-establishment blob, response ciphertext, signature) flowing over a protected "
        "connection, to decrypt it retroactively once a cryptographically relevant quantum "
        "computer exists. Distinguishes **bytes stored** from **bytes eventually decryptable** "
        "under a future CRQC — the RSA/ECDSA key-establishment blob in Configuration A is "
        "eventually decryptable (broken by Shor's algorithm); the ML-KEM-768 ciphertext in "
        "B/C is not (lattice-based)."
    )

    existing = dl.load_hndl_summaries()
    if existing:
        st.markdown("**Existing HNDL results (from `results/hndl/*-summary.json`):**")
        configs = [s["config"] for s in existing]
        projected = [s.get("projected_bytes_per_1000_requests") or 0 for s in existing]
        decryptable = [s.get("kex_decryptable_under_future_crqc") for s in existing]
        colors = ["#c0392b" if d else "#2471a3" for d in decryptable]
        fig = go.Figure(go.Bar(x=configs, y=projected, marker_color=colors))
        fig.update_layout(yaxis_title="Projected bytes stored per 1,000 requests", height=350)
        st.plotly_chart(fig, width='stretch')
        st.dataframe(existing, width='stretch')
    else:
        st.info("No HNDL results on disk yet.")

    st.divider()
    st.markdown("**Run a new HNDL capture:**")
    col1, col2, col3 = st.columns([1, 1, 1])
    with col1:
        hndl_config = st.selectbox("Configuration", ["classical", "hybrid", "full_pqc"], key="hndl_config")
    with col2:
        hndl_n = st.number_input("Requests to capture", min_value=10, max_value=2000, value=200, step=10)
    with col3:
        st.write("")
        st.write("")
        run_hndl = st.button("Run HNDL capture", type="primary")

    if run_hndl:
        from threats.hndl_capture import capture, summarize as hndl_summarize

        with st.spinner(f"Starting {server_manager.DISPLAY_NAME[hndl_config]} server if needed..."):
            base_url = server_manager.ensure_server(hndl_config)

        with st.spinner(f"Capturing {hndl_n} requests..."):
            rows = asyncio.run(capture(hndl_config, base_url, int(hndl_n)))
            result_summary = hndl_summarize(rows, hndl_config)

        st.success("Capture complete.")
        m1, m2, m3 = st.columns(3)
        m1.metric("Bytes stored / request (mean)", f"{result_summary['bytes_per_request_mean']:.0f}"
                   if result_summary["bytes_per_request_mean"] else "—")
        m2.metric("Projected bytes / 1,000 requests", f"{result_summary['projected_bytes_per_1000_requests']:,.0f}"
                   if result_summary["projected_bytes_per_1000_requests"] else "—")
        m3.metric("Key-exchange decryptable under future CRQC?",
                   "YES" if result_summary["kex_decryptable_under_future_crqc"] else "NO")
        with st.expander("Full summary"):
            st.json(result_summary)

        os.makedirs(dl.HNDL_DIR, exist_ok=True)
        out_path = os.path.join(dl.HNDL_DIR, f"{hndl_config}-hndl-summary.json")
        with open(out_path, "w") as f:
            json.dump(result_summary, f, indent=2)
        st.caption(f"Saved to {out_path}. Refresh the page to see it in the chart above.")

# ---------------------------------------------------------------------------
# MITM
# ---------------------------------------------------------------------------
with tab_mitm:
    st.markdown(
        "Injects a tamper into the response — corrupting either the AES-GCM ciphertext (caught "
        "at the authenticated-encryption layer, before signature verification is even reached) "
        "or the signature field specifically (isolating ECDSA vs. ML-DSA-65 tamper-detection "
        "behavior) — and measures detection rate and latency. This uses the same tamper function "
        "as `threats/mitm_harness.py`'s network proxy, applied locally for a fast in-browser demo; "
        "the CLI script (`scripts/run_threat_experiments.sh`) runs the full network-proxy version "
        "used for the paper's reported numbers."
    )

    existing_mitm = dl.load_mitm_summaries()
    if existing_mitm:
        st.markdown("**Existing MITM results (from `results/mitm/*-summary.json`):**")
        labels = [f"{s['config']} ({s['tamper_target']})" for s in existing_mitm]
        rates = [(s.get("detection_rate") or 0) * 100 for s in existing_mitm]
        det_ms = [s.get("detection_ms_mean") or 0 for s in existing_mitm]
        c1, c2 = st.columns(2)
        with c1:
            fig_rate = go.Figure(go.Bar(x=labels, y=rates, marker_color="#2471a3"))
            fig_rate.update_layout(yaxis_title="Detection rate (%)", height=350, yaxis_range=[0, 105])
            st.plotly_chart(fig_rate, width='stretch')
        with c2:
            fig_ms = go.Figure(go.Bar(x=labels, y=det_ms, marker_color="#e67e22"))
            fig_ms.update_layout(yaxis_title="Mean detection latency (ms)", height=350)
            st.plotly_chart(fig_ms, width='stretch')
        st.dataframe(existing_mitm, width='stretch')
    else:
        st.info("No MITM results on disk yet.")

    st.divider()
    st.markdown("**Run a new tamper-detection demo:**")
    col1, col2, col3, col4 = st.columns([1, 1, 1, 1])
    with col1:
        mitm_config = st.selectbox("Configuration", ["classical", "hybrid", "full_pqc"], key="mitm_config")
    with col2:
        mitm_target = st.selectbox("Tamper target", ["ciphertext", "signature"], key="mitm_target")
    with col3:
        mitm_n = st.number_input("Trials", min_value=5, max_value=200, value=25, step=5)
    with col4:
        st.write("")
        st.write("")
        run_mitm = st.button("Run tamper-detection demo", type="primary")

    if run_mitm:
        with st.spinner(f"Starting {server_manager.DISPLAY_NAME[mitm_config]} server if needed..."):
            base_url = server_manager.ensure_server(mitm_config)

        features, _, _ = demo_transaction.get_sample(0)

        async def _run_trials():
            results = []
            for _ in range(int(mitm_n)):
                row = await demo_transaction.run_secure_transaction(
                    base_url, mitm_config, features, tamper_target=mitm_target
                )
                results.append(row)
            return results

        with st.spinner(f"Running {mitm_n} tampered trials..."):
            trials = asyncio.run(_run_trials())

        n = len(trials)
        n_detected = sum(
            1 for r in trials
            if r.get("valid_signature") is False or (r.get("error") and "tampered" in str(r.get("error")).lower())
        )
        detect_times = [
            r.get("verify_ms") if mitm_target == "signature" else r.get("rtt_ms")
            for r in trials
            if (r.get("valid_signature") is False) or (r.get("decryption_ok") is False)
        ]
        detect_times = [t for t in detect_times if t is not None]

        st.success(f"{n_detected}/{n} tampered responses detected and rejected.")
        m1, m2 = st.columns(2)
        m1.metric("Detection rate", f"{n_detected / n:.0%}" if n else "—")
        m2.metric("Mean detection latency (ms)",
                   f"{sum(detect_times) / len(detect_times):.2f}" if detect_times else "—")

        result_summary = {
            "config": mitm_config, "tamper_target": mitm_target, "n_requests": n,
            "n_detected": n_detected, "detection_rate": n_detected / n if n else None,
            "detection_ms_mean": sum(detect_times) / len(detect_times) if detect_times else None,
        }
        os.makedirs(dl.MITM_DIR, exist_ok=True)
        out_path = os.path.join(dl.MITM_DIR, f"{mitm_config}-mitm-{mitm_target}-summary.json")
        with open(out_path, "w") as f:
            json.dump(result_summary, f, indent=2)
        st.caption(f"Saved to {out_path}. Refresh the page to see it in the chart above.")

        with st.expander("Raw trial records"):
            st.json(trials)

# ---------------------------------------------------------------------------
# Streaming sequence-integrity attack (drop / reorder a chunk mid-stream)
# ---------------------------------------------------------------------------
with tab_streaming_mitm:
    st.markdown(
        "Byte-corruption (the MITM tab) is caught **immediately** by AES-GCM authentication "
        "in every streaming strategy, the instant the tampered chunk arrives — that threat isn't "
        "differentiated by strategy, so re-running it here wouldn't teach anything new. What *is* "
        "strategy-dependent is a **sequence-integrity attack**: an attacker silently drops or "
        "reorders a chunk without touching any single chunk's bytes. `per_chunk` signs each "
        "chunk's position, so a client catches this on the very next chunk. `hash_chain` "
        "deliberately defers its sequence guarantee to the *terminating* signature to amortize "
        "signing cost — so this measures how much of the response a client would already have "
        "received (and, in a real chat UI, likely already shown the user) before the tamper is "
        "caught. `buffer_and_sign` delivers nothing before the end regardless, so it has no such "
        "exposure window and is marked not-applicable rather than given a fabricated number."
    )

    existing_stream_mitm = dl.load_streaming_mitm_summaries()
    if existing_stream_mitm:
        st.markdown("**Existing results (from `results/streaming/mitm/*-summary.json`):**")
        attackable = [s for s in existing_stream_mitm if s.get("detection_rate") is not None]
        if attackable:
            labels = [f"{s['config']} / {s['strategy']} / {s['attack']}" for s in attackable]
            fractions = [(s.get("fraction_delivered_before_detection_mean") or 0) * 100 for s in attackable]
            mid_rates = [(s.get("mid_stream_detection_rate") or 0) * 100 for s in attackable]
            c1, c2 = st.columns(2)
            with c1:
                fig_frac = go.Figure(go.Bar(x=labels, y=fractions, marker_color="#c0392b"))
                fig_frac.update_layout(
                    yaxis_title="% of response delivered before detection", height=380, yaxis_range=[0, 105],
                    xaxis_tickangle=-30,
                )
                st.plotly_chart(fig_frac, width='stretch')
            with c2:
                fig_mid = go.Figure(go.Bar(x=labels, y=mid_rates, marker_color="#2471a3"))
                fig_mid.update_layout(
                    yaxis_title="Mid-stream detection rate (%)", height=380, yaxis_range=[0, 105],
                    xaxis_tickangle=-30,
                )
                st.plotly_chart(fig_mid, width='stretch')
        st.dataframe(existing_stream_mitm, width='stretch')
    else:
        st.info("No streaming sequence-attack results on disk yet.")

    st.divider()
    st.markdown("**Run a new sequence-attack demo:**")
    col1, col2, col3, col4 = st.columns([1, 1, 1, 1])
    with col1:
        sm_config = st.selectbox("Configuration", ["classical", "hybrid", "full_pqc"], key="sm_config")
    with col2:
        sm_strategy = st.selectbox("Strategy", ["per_chunk", "hash_chain"], key="sm_strategy",
                                    help="buffer_and_sign has no intermediate chunks to attack.")
    with col3:
        sm_attack = st.selectbox("Attack", ["drop", "reorder"], key="sm_attack")
    with col4:
        sm_trials = st.number_input("Trials", min_value=3, max_value=100, value=10, step=1)

    sm_run = st.button("Run sequence-attack demo", type="primary")

    if sm_run:
        from threats.streaming_mitm_experiment import run_trial, summarize as sm_summarize

        with st.spinner(f"Starting {server_manager.DISPLAY_NAME[sm_config]} server if needed..."):
            base_url = server_manager.ensure_server(sm_config)

        async def _run_sm_trials():
            import httpx
            results = []
            async with httpx.AsyncClient(timeout=60.0) as client:
                for _ in range(int(sm_trials)):
                    row = await run_trial(client, base_url, sm_config, sm_strategy, sm_attack)
                    results.append(row)
            return results

        with st.spinner(f"Running {sm_trials} {sm_attack} trials against {sm_strategy}..."):
            sm_trial_rows = asyncio.run(_run_sm_trials())

        sm_result_summary = sm_summarize(sm_trial_rows, sm_config, sm_strategy, sm_attack)

        if sm_result_summary["detection_rate"] is None:
            st.warning("All trials errored — see raw records below (streams may be too short; try more max_tokens).")
        else:
            st.success(
                f"Detected {sm_result_summary['detection_rate']:.0%} of tampered streams "
                f"({sm_result_summary['mid_stream_detection_rate']:.0%} mid-stream, before the response finished)."
            )
            m1, m2, m3 = st.columns(3)
            m1.metric("Detection rate", f"{sm_result_summary['detection_rate']:.0%}")
            m2.metric("Mid-stream detection rate", f"{sm_result_summary['mid_stream_detection_rate']:.0%}")
            m3.metric(
                "Response delivered before detection",
                f"{sm_result_summary['fraction_delivered_before_detection_mean']:.0%}"
                if sm_result_summary["fraction_delivered_before_detection_mean"] is not None else "—",
            )

            os.makedirs(dl.STREAMING_MITM_DIR, exist_ok=True)
            out_path = os.path.join(dl.STREAMING_MITM_DIR, f"{sm_config}-{sm_strategy}-{sm_attack}-summary.json")
            with open(out_path, "w") as f:
                json.dump(sm_result_summary, f, indent=2)
            st.caption(f"Saved to {out_path}. Refresh the page to see it in the chart above.")

        with st.expander("Raw trial records"):
            st.json(sm_trial_rows)

# ---------------------------------------------------------------------------
# Streaming HNDL exposure scaling (confidentiality, NOT sequence integrity --
# see docs/STREAMING.md section 10 for why this is a distinct finding from
# the tab above, and why signature/chain-hash bytes are excluded here)
# ---------------------------------------------------------------------------
with tab_streaming_hndl:
    st.markdown(
        "The **HNDL** tab above measures one small, fixed-size response. A streamed response "
        "reuses **one handshake's session key across every chunk of a potentially long-running "
        "stream** — so if that handshake is later broken, an adversary who harvested the whole "
        "session recovers *everything it ever streamed*, not one small reply. This is **not a new "
        "vulnerability class** — it's the same Shor's-algorithm-breaks-RSA/ECDH threat, made worse "
        "in direct proportion to response length. Only `kex_blob` and each chunk's `(nonce, "
        "ciphertext)` count toward *harvestable* bytes here — signatures and chain hashes protect "
        "authenticity, not confidentiality, and are tracked separately (see the strategy-"
        "independence check below, and the *separate* 🌊 Streaming Sequence Attack tab for what "
        "signatures/chain-hash timing metadata actually exposes)."
    )

    existing_stream_hndl = dl.load_streaming_hndl_summaries()
    if existing_stream_hndl:
        st.markdown("**Existing results (from `results/hndl/streaming/*-streaming-hndl-summary.json`):**")
        fig_exposure = go.Figure()
        for s in existing_stream_hndl:
            color = "#c0392b" if s.get("kex_decryptable_under_future_crqc") else "#2471a3"
            fig_exposure.add_trace(go.Scatter(
                x=s.get("max_tokens_values", []),
                y=s.get("decryptable_bytes_under_future_crqc_by_length", []),
                mode="lines+markers", name=s["config"], line=dict(color=color), marker=dict(color=color),
            ))
        fig_exposure.update_layout(
            xaxis_title="Response length (max_tokens)", yaxis_title="Bytes decryptable under a future CRQC",
            height=380, legend=dict(orientation="h", yanchor="bottom", y=-0.3),
        )
        st.plotly_chart(fig_exposure, width='stretch')
        st.caption(
            "Red = key-establishment decryptable under a future CRQC (RSA/ECDH); blue = not "
            "(ML-KEM-768, lattice-based). Hybrid and full_pqc's lines overlap at zero regardless "
            "of length — both fully protect confidentiality here."
        )
        st.dataframe(existing_stream_hndl, width='stretch')

        existing_independence = dl.load_streaming_hndl_independence()
        if existing_independence:
            st.markdown("**Strategy-independence check** (does signing strategy affect confidentiality exposure?)")
            for ind in existing_independence:
                match = "✅ exact match" if ind.get("exact_match_across_strategies") else "see byte deltas below"
                st.markdown(f"- **{ind['config']}** @ max_tokens={ind['max_tokens']}: "
                             f"`{ind['total_bytes_harvestable_by_strategy']}` — {match}")
            with st.expander("Full strategy-independence details (AEAD-envelope-overhead explanation)"):
                st.json(existing_independence)
    else:
        st.info("No streaming HNDL results on disk yet.")

    st.divider()
    st.markdown("**Run a new streaming HNDL length sweep:**")
    col1, col2, col3 = st.columns([1, 2, 1])
    with col1:
        sh_config = st.selectbox("Configuration", ["classical", "hybrid", "full_pqc"], key="sh_config")
    with col2:
        sh_max_tokens = st.text_input("Response lengths (comma-separated)", value="50,200,500,2000", key="sh_max_tokens")
    with col3:
        sh_chunk_size = st.number_input("Chunk size (tokens)", min_value=1, max_value=50, value=5, key="sh_chunk_size")
    sh_run = st.button("Run streaming HNDL sweep", type="primary")

    if sh_run:
        from threats.streaming_hndl_experiment import run_one_config

        try:
            sh_lengths = [int(x.strip()) for x in sh_max_tokens.split(",") if x.strip()]
        except ValueError:
            sh_lengths = []

        if not sh_lengths:
            st.error("Enter at least one valid response length.")
        else:
            with st.spinner(f"Starting {server_manager.DISPLAY_NAME[sh_config]} server if needed..."):
                base_url = server_manager.ensure_server(sh_config)

            with st.spinner(f"Sweeping {len(sh_lengths)} response lengths + strategy-independence check..."):
                sh_result = asyncio.run(run_one_config(base_url, sh_config, sh_lengths, int(sh_chunk_size), "per_chunk"))

            sh_summary = sh_result["sweep_summary"]
            st.success(
                f"kex_decryptable_under_future_crqc = {sh_summary['kex_decryptable_under_future_crqc']}  "
                f"({sh_summary['fraction_of_harvested_bytes_eventually_decryptable']:.0%} of harvested bytes "
                f"eventually decryptable)"
            )
            m1, m2, m3 = st.columns(3)
            m1.metric("Response lengths swept", sh_summary["n_lengths"])
            m2.metric("Harvestable bytes (longest)", f"{sh_summary['total_bytes_harvestable_by_length'][-1]:,}"
                       if sh_summary["total_bytes_harvestable_by_length"] else "—")
            m3.metric("Monotonic in length?", "✅ Yes" if sh_summary["harvestable_bytes_monotonic_in_length"] else "❌ No")

            ind = sh_result["strategy_independence"]
            st.markdown("**Strategy-independence check:**")
            st.json({k: v for k, v in ind.items() if k != "rows"})

            os.makedirs(dl.STREAMING_HNDL_DIR, exist_ok=True)
            crypto_name = sh_config
            from threats.streaming_hndl_experiment import _write_csv

            _write_csv(sh_result["sweep_rows"], os.path.join(dl.STREAMING_HNDL_DIR, f"{crypto_name}-streaming-hndl.csv"))
            with open(os.path.join(dl.STREAMING_HNDL_DIR, f"{crypto_name}-streaming-hndl-summary.json"), "w") as f:
                json.dump(sh_summary, f, indent=2)
            with open(os.path.join(dl.STREAMING_HNDL_DIR, f"{crypto_name}-strategy-independence.json"), "w") as f:
                json.dump({k: v for k, v in ind.items() if k != "rows"}, f, indent=2)
            st.caption(f"Saved to {dl.STREAMING_HNDL_DIR}/. Refresh the page to see it in the chart above.")

# ---------------------------------------------------------------------------
# AI summary
# ---------------------------------------------------------------------------
st.divider()
st.subheader("🤖 AI Summary")

from webapp import ai_summary

if not ai_summary.api_key_present():
    st.info(
        "Set `ANTHROPIC_API_KEY` in `.env` (repo root) to enable an AI-generated "
        "summary of the threat-scenario results above."
    )
else:
    st.caption(
        "Sends the HNDL, MITM, streaming sequence-attack, and streaming HNDL summary JSON shown "
        "above (not raw per-trial records) to Claude for a plain-language security readout."
    )
    if st.button("Generate AI summary", type="primary", key="threat_ai_summary_btn"):
        context = ai_summary.build_threat_context(
            hndl_summaries=dl.load_hndl_summaries(),
            mitm_summaries=dl.load_mitm_summaries(),
            streaming_mitm_summaries=dl.load_streaming_mitm_summaries(),
            streaming_hndl_summaries=dl.load_streaming_hndl_summaries(),
            streaming_hndl_independence=dl.load_streaming_hndl_independence(),
        )
        try:
            with st.spinner("Asking Claude..."):
                text = ai_summary.generate_threat_summary(context)
            st.markdown(text)
        except Exception as exc:
            st.error(f"AI summary failed: {exc}")
