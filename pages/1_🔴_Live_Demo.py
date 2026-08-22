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

# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Server status panel
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

# ---------------------------------------------------------------------------
# Run the transaction
# ---------------------------------------------------------------------------
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
        metric_cols[0].metric("RTT (ms)", f"{row.get('rtt_ms', 0):.2f}" if row.get("rtt_ms") is not None else "—")
        if config_name != "control":
            metric_cols[1].metric(
                "Handshake (ms)", f"{row.get('handshake_ms', 0):.2f}" if row.get("handshake_ms") is not None else "—"
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
