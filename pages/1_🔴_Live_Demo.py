import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from webapp.bootstrap import load_dotenv_if_needed

load_dotenv_if_needed()

import matplotlib.pyplot as plt
import plotly.graph_objects as go
import streamlit as st

from webapp import demo_transaction, server_manager

st.set_page_config(page_title="PQ-Shield — Live Demo", page_icon="🔴", layout="wide")
st.title("🔴 Live Demo")
st.caption(
    "Sends one real HTTP request through an actual running server for the chosen "
    "configuration — the exact same server and client code as the benchmark, just one "
    "transaction at a time."
)

CRYPTO_NAMES = ["control", "classical", "hybrid", "full_pqc"]
STREAMING_CRYPTO_NAMES = ["classical", "hybrid", "full_pqc"]  # streaming needs a crypto config; no control
STRATEGY_LABELS = {
    "buffer_and_sign": "buffer_and_sign — sign once at the end (cheapest bytes, worst TTFT)",
    "per_chunk": "per_chunk — sign every chunk (best TTFT, most signature bytes)",
    "hash_chain": "hash_chain — hash-chain + one terminating signature (best of both)",
}

# ---------------------------------------------------------------------------
# Server status panel (shared by both tabs below)
# ---------------------------------------------------------------------------
with st.expander("Demo server status", expanded=False):
    status = server_manager.server_status()
    cols = st.columns(len(status))
    for col, (name, info) in zip(cols, status.items()):
        with col:
            st.markdown(f"**{server_manager.DISPLAY_NAME[name]}**")
            st.write("🟢 Running" if info["running"] else "⚪ Not running")
            st.caption(info["base_url"])
            if info["running"] and st.button("Stop", key=f"stop_{name}"):
                server_manager.stop_server(name)
                st.rerun()

tab_single, tab_streaming = st.tabs(["Single Prediction", "🌊 Streaming Response (SSE)"])

# =============================================================================
# Tab 1: single-shot prediction (unchanged from before)
# =============================================================================
with tab_single:
    left, right = st.columns([1, 2])

    with left:
        config_name = st.selectbox(
            "Configuration",
            CRYPTO_NAMES,
            format_func=lambda c: server_manager.DISPLAY_NAME[c],
        )

        sample_idx = st.slider("Test digit sample", 0, demo_transaction.n_samples() - 1, 0)
        features, image, true_label = demo_transaction.get_sample(sample_idx)

        fig, ax = plt.subplots(figsize=(2.2, 2.2))
        ax.imshow(image, cmap="gray_r")
        ax.set_title(f"True label: {true_label}", fontsize=10)
        ax.axis("off")
        st.pyplot(fig, width='content')
        plt.close(fig)

        tamper_target = None
        if config_name != "control":
            tamper_choice = st.radio(
                "Simulate tampering with the response",
                ["None", "Corrupt ciphertext (AEAD layer)", "Corrupt signature (signature layer)"],
                help=(
                    "Demonstrates the same tamper-injection this project's threats/mitm_harness.py "
                    "performs over the network, applied locally to the response bytes before "
                    "decrypt/verify — shows exactly what an active man-in-the-middle attacker "
                    "flipping one byte would trigger."
                ),
            )
            tamper_target = {
                "None": None,
                "Corrupt ciphertext (AEAD layer)": "ciphertext",
                "Corrupt signature (signature layer)": "signature",
            }[tamper_choice]

        send_clicked = st.button("Send request", type="primary", width='stretch')

    if send_clicked:
        with st.spinner(f"Starting {server_manager.DISPLAY_NAME[config_name]} server if needed..."):
            base_url = server_manager.ensure_server(config_name)

        with st.spinner("Running transaction..."):
            if config_name == "control":
                row = asyncio.run(demo_transaction.run_control_transaction(base_url, features))
            else:
                row = asyncio.run(
                    demo_transaction.run_secure_transaction(base_url, config_name, features, tamper_target)
                )

        with right:
            st.subheader("Result")

            if row.get("error") and row.get("decryption_ok") is False:
                st.error(f"❌ TAMPER DETECTED — {row['error']}")
            elif row.get("error"):
                st.error(f"Request failed: {row['error']}")
            else:
                st.success("✅ Transaction completed and verified successfully")

            if config_name != "control":
                badge_col1, badge_col2 = st.columns(2)
                with badge_col1:
                    if row.get("valid_signature") is True:
                        st.success("Signature: VALID")
                    elif row.get("valid_signature") is False:
                        st.error("Signature: REJECTED")
                with badge_col2:
                    if row.get("decryption_ok") is True:
                        st.success("AEAD decryption: OK")
                    elif row.get("decryption_ok") is False:
                        st.error("AEAD decryption: FAILED (tamper caught)")

            metric_cols = st.columns(4)
            metric_cols[0].metric(
                "RTT (ms)", f"{row.get('rtt_ms', 0):.2f}" if row.get("rtt_ms") is not None else "—"
            )
            if config_name != "control":
                metric_cols[1].metric(
                    "Handshake (ms)",
                    f"{row.get('handshake_ms', 0):.2f}" if row.get("handshake_ms") is not None else "—",
                )
                metric_cols[2].metric(
                    "Verify (ms)", f"{row.get('verify_ms', 0):.2f}" if row.get("verify_ms") is not None else "—"
                )
                sig_bytes = row.get("signature_bytes")
                metric_cols[3].metric("Signature bytes", sig_bytes if sig_bytes is not None else "—")

            if row.get("prediction") is not None:
                st.markdown(f"**Predicted digit: {row['prediction']}** (true label: {true_label})")
                probs = row.get("probabilities") or []
                if probs:
                    bar = go.Figure(
                        go.Bar(x=list(range(len(probs))), y=probs, marker_color="#2471a3")
                    )
                    bar.update_layout(
                        height=250, margin=dict(l=10, r=10, t=30, b=10),
                        xaxis_title="Digit class", yaxis_title="Probability",
                        title="Class probabilities",
                    )
                    st.plotly_chart(bar, width='stretch')

            if config_name != "control" and row.get("server_timing_ms"):
                st.markdown("**Server-side timing breakdown**")
                timing = row["server_timing_ms"]
                timing_bar = go.Figure(
                    go.Bar(
                        x=["Decapsulate", "Inference", "Encrypt", "Sign"],
                        y=[
                            timing.get("decapsulate_ms", 0),
                            timing.get("inference_ms", 0),
                            timing.get("encrypt_ms", 0),
                            timing.get("sign_ms", 0),
                        ],
                        marker_color="#e67e22",
                    )
                )
                timing_bar.update_layout(
                    height=250, margin=dict(l=10, r=10, t=10, b=10), yaxis_title="ms"
                )
                st.plotly_chart(timing_bar, width='stretch')

            with st.expander("Raw transaction record"):
                st.json(row)

# =============================================================================
# Tab 2: live SSE token streaming, verified chunk-by-chunk as it arrives
# =============================================================================
with tab_streaming:
    st.caption(
        "Sends one prompt to `POST /secure/predict/stream` and consumes the Server-Sent "
        "Event response live — each chunk is decrypted and verified the instant it arrives, "
        "using whichever of the three signing strategies (crypto/streaming.py) you pick below. "
        "See `docs/STREAMING.md` for the full design."
    )

    s_left, s_right = st.columns([1, 2])

    with s_left:
        stream_config_name = st.selectbox(
            "Configuration",
            STREAMING_CRYPTO_NAMES,
            format_func=lambda c: server_manager.DISPLAY_NAME[c],
            key="stream_config",
        )
        strategy = st.selectbox(
            "Signing strategy",
            list(STRATEGY_LABELS.keys()),
            format_func=lambda s: STRATEGY_LABELS[s],
            key="stream_strategy",
        )
        prompt = st.text_area(
            "Prompt", value="Explain quantum-safe cryptography in two short sentences.",
            key="stream_prompt",
        )
        max_tokens = st.slider("Max tokens", 10, 300, 60, key="stream_max_tokens")
        chunk_size_tokens = st.slider(
            "Chunk size (tokens per signed/hashed unit)", 1, 20, 5, key="stream_chunk_size",
            help="Ignored by buffer_and_sign, which never emits intermediate chunks.",
        )

        stream_tamper_choice = st.radio(
            "Simulate tampering with one chunk, live",
            ["None", "Corrupt a chunk's ciphertext (AEAD layer)", "Corrupt the signature"],
            key="stream_tamper_choice",
            help=(
                "Applied locally to the decoded bytes the instant that chunk arrives — the same "
                "live tamper-injection the single-prediction tab does, extended to one position in "
                "a stream. For buffer_and_sign and hash_chain, 'Corrupt the signature' always targets "
                "the one terminating signature (they only sign once); only per_chunk signs every "
                "chunk individually, so the index selector below applies to it specifically."
            ),
        )
        stream_tamper_target = {
            "None": None,
            "Corrupt a chunk's ciphertext (AEAD layer)": "ciphertext",
            "Corrupt the signature": "signature",
        }[stream_tamper_choice]

        stream_tamper_index = None
        if stream_tamper_target is not None:
            if strategy == "buffer_and_sign":
                st.caption("buffer_and_sign has one final envelope — that's what gets corrupted.")
                stream_tamper_index = 0
            elif stream_tamper_target == "signature" and strategy == "hash_chain":
                st.caption("hash_chain signs only the final chain hash — that's what gets corrupted.")
                stream_tamper_index = 0
            else:
                stream_tamper_index = st.number_input(
                    "Chunk index to corrupt (0-based)", min_value=0, value=1, step=1,
                    key="stream_tamper_index",
                )

        stream_send_clicked = st.button("Start streaming", type="primary", width='stretch', key="stream_send")

    with s_right:
        if stream_send_clicked:
            with st.spinner(f"Starting {server_manager.DISPLAY_NAME[stream_config_name]} server if needed..."):
                stream_base_url = server_manager.ensure_server(stream_config_name)

            st.subheader("Live response")
            verified_banner = st.empty()
            text_placeholder = st.empty()
            chunk_log = st.container(height=180)
            metrics_placeholder = st.empty()

            text_parts: list[str] = []
            chunk_rows: list[str] = []

            async def _consume():
                async for event in demo_transaction.run_streaming_transaction_live(
                    stream_base_url, stream_config_name, prompt, strategy,
                    chunk_size_tokens=chunk_size_tokens, max_tokens=max_tokens,
                    tamper_chunk_index=stream_tamper_index, tamper_target=stream_tamper_target or "ciphertext",
                ):
                    etype = event.get("type")

                    if etype == "chunk":
                        if event.get("text"):
                            text_parts.append(event["text"])
                            text_placeholder.markdown("".join(text_parts) + " ▌")

                        ok = event.get("aead_ok")
                        sig_ok = event.get("signature_valid")
                        chain_ok = event.get("chain_ok_so_far")
                        bits = [f"chunk {event['index']}"]
                        if sig_ok is not None:
                            bits.append("sig ✅" if sig_ok else "sig ❌")
                        if chain_ok is not None:
                            bits.append("chain ✅" if chain_ok else "chain ❌")
                        bits.append("AEAD ✅" if ok else "AEAD ❌")
                        if event.get("in_order") is False:
                            bits.append("OUT OF ORDER ⚠️")
                        if event.get("tampered"):
                            bits.append("🧪 tampered here")
                        line = " · ".join(bits)
                        chunk_rows.append(line)
                        with chunk_log:
                            if "❌" in line or "⚠️" in line:
                                st.error(line)
                            else:
                                st.caption(line)

                    elif etype == "final":
                        if event.get("text"):
                            text_parts.append(event["text"])
                        text_placeholder.markdown("".join(text_parts) if text_parts else "*(no text buffered)*")
                        if event["stream_fully_verified"]:
                            verified_banner.success("✅ Stream fully verified end-to-end")
                        else:
                            verified_banner.error(
                                "❌ TAMPER DETECTED — verification failed"
                                if event.get("tampered") else
                                "❌ Stream verification FAILED"
                            )

                    elif etype == "summary":
                        m = event["metrics"]
                        with metrics_placeholder.container():
                            mcols = st.columns(4)
                            mcols[0].metric(
                                "Time to first token",
                                f"{m['ttft_ms']:.0f} ms" if m.get("ttft_ms") is not None else "—",
                            )
                            mcols[1].metric(
                                "Total time", f"{m['total_ms']:.0f} ms" if m.get("total_ms") is not None else "—"
                            )
                            mcols[2].metric("Chunks", m.get("n_chunks", 0))
                            mcols[3].metric("Signature bytes (total)", m.get("total_signature_bytes", 0))
                            with st.expander("Raw metrics"):
                                st.json(m)

                    elif etype == "error":
                        verified_banner.error(f"Request failed: {event['message']}")

            asyncio.run(_consume())
        else:
            st.info("Set your parameters and click **Start streaming** to watch a live, verified SSE response.")
