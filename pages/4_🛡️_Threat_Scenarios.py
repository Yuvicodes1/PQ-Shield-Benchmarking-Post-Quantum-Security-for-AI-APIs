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

tab_hndl, tab_mitm, tab_streaming_mitm = st.tabs([
    "Harvest-Now-Decrypt-Later (HNDL)", "Man-in-the-Middle (MITM)", "🌊 Streaming Sequence Attack",
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
        "Sends the HNDL, MITM, and streaming sequence-attack summary JSON shown above (not raw "
        "per-trial records) to Claude for a plain-language security readout."
    )
    if st.button("Generate AI summary", type="primary", key="threat_ai_summary_btn"):
        context = ai_summary.build_threat_context(
            hndl_summaries=dl.load_hndl_summaries(),
            mitm_summaries=dl.load_mitm_summaries(),
            streaming_mitm_summaries=dl.load_streaming_mitm_summaries(),
        )
        try:
            with st.spinner("Asking Claude..."):
                text = ai_summary.generate_threat_summary(context)
            st.markdown(text)
        except Exception as exc:
            st.error(f"AI summary failed: {exc}")
