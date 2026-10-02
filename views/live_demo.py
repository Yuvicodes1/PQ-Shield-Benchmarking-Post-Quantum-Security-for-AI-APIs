import asyncio
import html

import matplotlib.pyplot as plt
import plotly.graph_objects as go
import streamlit as st

from webapp import demo_transaction, server_manager, ui
from webapp.colors import CONFIG_COLORS

ui.page_header(
    "Live demo",
    "Real requests through real servers — the same server and client code as the benchmark, one transaction "
    "at a time. Stream a Llama response and watch each chunk get decrypted and verified, or attack the stream "
    "on the wire and see where the client catches it.",
    eyebrow="Interactive",
)

STREAMING = ["classical", "classical_ecdhe", "hybrid", "hybrid_kex", "full_pqc", "hybrid_kex_pq"]
STRATEGIES = {"per_chunk": "Per-chunk", "hash_chain": "Hash chain", "buffer_and_sign": "Buffer & sign"}
STRATEGY_HELP = {
    "per_chunk": "Every chunk carries its own signature: nothing is shown unverified, most signature bytes.",
    "hash_chain": "Chunks are chained by hash; a checkpoint signature every k chunks (or one at the end) covers "
                  "everything before it. Text is shown before a signature covers it.",
    "buffer_and_sign": "Nothing is shown until the whole response is generated and signed once.",
}

with st.popover("Demo servers", icon=":material/dns:"):
    status = server_manager.server_status()
    for name, info in status.items():
        c1, c2 = st.columns([3, 1])
        c1.markdown(f"{'🟢' if info['running'] else '⚪'} **{ui.SHORT[name]}** · `:{info['port']}`")
        if info["running"] and c2.button("Stop", key=f"stop_{name}"):
            server_manager.stop_server(name)
            st.rerun()

tab_stream, tab_single = st.tabs([":material/stream: Streaming response", ":material/send: Single request"])

# ============================================================================ streaming
with tab_stream:
    left, right = st.columns([1, 1.7], gap="large")
    with left:
        with st.container(border=True):
            cfg = st.selectbox("Configuration", STREAMING, index=4, format_func=ui.label, key="ls_cfg")
            strategy = st.segmented_control("Signing strategy", list(STRATEGIES), default="hash_chain",
                                            format_func=STRATEGIES.get, key="ls_strategy") or "hash_chain"
            st.caption(STRATEGY_HELP[strategy])
            k = None
            enforce = True
            if strategy == "hash_chain":
                k_opt = st.select_slider("Checkpoint every k chunks", ["off", 1, 2, 3, 5, 10], value=3, key="ls_k")
                k = None if k_opt == "off" else int(k_opt)
            prompt = st.text_area("Prompt", "Explain quantum-safe cryptography in three short sentences.",
                                  height=80, key="ls_prompt")
            c1, c2 = st.columns(2)
            max_tokens = c1.slider("Max tokens", 20, 300, 100, step=10, key="ls_max")
            chunk = c2.slider("Tokens per chunk", 1, 20, 5, key="ls_chunk")

        with st.container(border=True):
            st.markdown("**On-path attacker**")
            allowed = [None, "tamper_ciphertext", "tamper_signature", "truncate"]
            if strategy != "buffer_and_sign":
                allowed += ["drop", "reorder", "duplicate"]
            if strategy == "hash_chain" and k:
                allowed += ["strip_checkpoints"]
            attack = st.selectbox("Attack", allowed, format_func=demo_transaction.STREAM_ATTACKS.get, key="ls_attack")
            attack_index = 2
            if attack and attack not in ("strip_checkpoints",) and strategy != "buffer_and_sign":
                attack_index = st.number_input("At chunk index", 0, 200, 2, key="ls_idx")
            if attack == "strip_checkpoints":
                enforce = st.toggle("Client enforces the checkpoint schedule it requested", value=True,
                                    help="Turn off to see the old client accept a stream whose checkpoints were "
                                         "stripped — content genuine, mid-stream assurance silently gone.")
        go_btn = st.button("Start streaming", type="primary", icon=":material/play_arrow:", width="stretch")

    with right:
        legend = ('<div class="pq-legend"><span class="pq-tok-verified">verified</span> · '
                  '<span class="pq-tok-pending">shown, not yet covered by a signature</span> · '
                  '<span class="pq-tok-rejected">rejected</span></div>')
        if not go_btn:
            with st.container(border=True):
                st.markdown(f"{ui.chip(cfg)} &nbsp; **{STRATEGIES[strategy]}**"
                            + (f" · checkpoint every {k} chunks" if k else ""), unsafe_allow_html=True)
                st.caption("Press **Start streaming**. Requires the Llama backend "
                           "(`PQ_SHIELD_STREAMING_BACKEND=llama_cpp`) or falls back to the synthetic generator.")
        else:
            with st.spinner(f"Starting the {ui.SHORT[cfg]} server…"):
                base_url = server_manager.ensure_server(cfg)
            banner = st.empty()
            text_box = st.empty()
            st.html(legend)
            counters = st.empty()
            log = st.expander("Record-by-record log", icon=":material/list:")

            tokens: list[list] = []  # [text, status]
            live = {"chunks": 0, "pending": 0, "max_pending": 0, "final": None}

            def render():
                spans = "".join(f'<span class="pq-tok-{s}">{html.escape(t)}</span>' for t, s in tokens) or "&nbsp;"
                text_box.markdown(f'<div class="pq-stream">{spans}</div>', unsafe_allow_html=True)
                with counters.container():
                    m = st.columns(3)
                    m[0].metric("Chunks received", live["chunks"])
                    m[1].metric("Shown unverified now", live["pending"])
                    m[2].metric("Most shown unverified", live["max_pending"])

            async def consume():
                async for ev in demo_transaction.run_streaming_transaction_live(
                        base_url, cfg, prompt, strategy, chunk_size_tokens=chunk, max_tokens=max_tokens,
                        checkpoint_interval=k, attack=attack, attack_index=int(attack_index),
                        enforce_schedule=enforce):
                    t = ev["type"]
                    if t == "chunk":
                        live["chunks"] += 1
                        if ev["text"]:
                            tokens.append([ev["text"], ev["status"]])
                        if ev["status"] == "pending":
                            live["pending"] += 1
                            live["max_pending"] = max(live["max_pending"], live["pending"])
                        flag = " ← attacked" if ev.get("attacked") else ""
                        line = f"chunk {ev['index']}: {ev['status']}{(' — ' + ev['reason']) if ev['reason'] else ''}{flag}"
                        (log.error if ev["status"] == "rejected" else log.caption)(line)
                        if ev["status"] == "rejected" and not live["final"]:
                            banner.error(f"Rejected at chunk {ev['index']}: {ev['reason']}", icon=":material/gpp_bad:")
                    elif t == "covered":
                        for tok in tokens:
                            if tok[1] == "pending":
                                tok[1] = "verified"
                        live["pending"] = 0
                        log.caption(f"✓ checkpoint verified — chunks 0–{ev['upto']} covered")
                    elif t == "final":
                        live["final"] = ev
                        if ev.get("text"):
                            tokens.append([ev["text"], "verified" if ev["stream_fully_verified"] else "rejected"])
                        if ev["stream_fully_verified"]:
                            banner.success("Stream fully verified end to end", icon=":material/verified_user:")
                        else:
                            for tok in tokens:
                                if tok[1] == "pending":
                                    tok[1] = "rejected"
                            banner.error(f"Verification failed — {ev['reason']}", icon=":material/gpp_bad:")
                    elif t == "summary":
                        mt = ev["metrics"]
                        render()
                        with st.container(border=True):
                            s = st.columns(4)
                            s[0].metric("Time to first token", f"{mt['ttft_ms']:.0f} ms" if mt.get("ttft_ms") else "—")
                            s[1].metric("Signatures", mt["n_signatures"])
                            s[2].metric("Signature bytes", f"{mt['total_signature_bytes']:,}")
                            s[3].metric("Server signing (CPU)", f"{mt['total_signing_cpu_ms']:.2f} ms")
                            with st.expander("Raw metrics"):
                                st.json(mt)
                        return
                    elif t == "error":
                        banner.error(f"Request failed: {ev['message']}")
                        return
                    render()

            asyncio.run(consume())

# ============================================================================ single request
with tab_single:
    left, right = st.columns([1, 1.7], gap="large")
    with left:
        with st.container(border=True):
            cfg1 = st.selectbox("Configuration", ["control"] + STREAMING, index=5, format_func=ui.label, key="ss_cfg")
            idx = st.slider("Handwritten digit sample", 0, demo_transaction.n_samples() - 1, 0, key="ss_idx")
            features, image, true_label = demo_transaction.get_sample(idx)
            fig, ax = plt.subplots(figsize=(1.6, 1.6))
            ax.imshow(image, cmap="gray_r")
            ax.axis("off")
            st.pyplot(fig, width="content")
            plt.close(fig)
            tamper = None
            if cfg1 != "control":
                tamper = st.radio("Tamper with the response", [None, "ciphertext", "signature"],
                                  format_func=lambda t: {None: "No tampering", "ciphertext": "Flip a ciphertext bit",
                                                         "signature": "Flip a signature bit"}[t], key="ss_tamper")
        send = st.button("Send request", type="primary", icon=":material/send:", width="stretch")

    with right:
        if not send:
            with st.container(border=True):
                st.caption("Sends one prediction request. Protected configurations perform a fresh key exchange, "
                           "encrypt the request, and verify the signed, encrypted response.")
        else:
            with st.spinner(f"Starting the {ui.SHORT[cfg1]} server…"):
                base_url = server_manager.ensure_server(cfg1)
            if cfg1 == "control":
                row = asyncio.run(demo_transaction.run_control_transaction(base_url, features))
            else:
                row = asyncio.run(demo_transaction.run_secure_transaction(base_url, cfg1, features, tamper))
            if row.get("error") and row.get("decryption_ok") is False:
                st.error(f"Tampering detected — {row['error']}", icon=":material/gpp_bad:")
            elif row.get("valid_signature") is False:
                st.error("Tampering detected — signature rejected", icon=":material/gpp_bad:")
            elif row.get("error"):
                st.error(f"Request failed: {row['error']}")
            else:
                st.success("Response decrypted and verified", icon=":material/verified_user:")
            m = st.columns(4)
            m[0].metric("Round trip", f"{row['rtt_ms']:.1f} ms" if row.get("rtt_ms") is not None else "—")
            m[1].metric("Handshake", f"{row['handshake_ms']:.1f} ms" if row.get("handshake_ms") is not None else "—")
            m[2].metric("Verify", f"{row['verify_ms']:.3f} ms" if row.get("verify_ms") is not None else "—")
            m[3].metric("Signature", f"{row['signature_bytes']:,} B" if row.get("signature_bytes") else "—")
            if row.get("prediction") is not None:
                st.markdown(f"**Predicted digit {row['prediction']}** · true label {true_label}")
                probs = row.get("probabilities") or []
                if probs:
                    bar = go.Figure(go.Bar(x=list(range(len(probs))), y=probs,
                                           marker_color=CONFIG_COLORS.get(cfg1, "#888888")))
                    bar.update_xaxes(title="Digit", dtick=1)
                    bar.update_yaxes(title="Probability")
                    ui.chart(ui.style_fig(bar, 230, legend=None))
            if cfg1 != "control" and row.get("server_timing_ms"):
                tm = row["server_timing_ms"]
                parts = [("Decapsulate", tm.get("decapsulate_ms", 0)), ("Inference", tm.get("inference_ms", 0)),
                         ("Encrypt", tm.get("encrypt_ms", 0)), ("Sign", tm.get("sign_ms", 0))]
                tb = go.Figure(go.Bar(y=[p[0] for p in parts], x=[p[1] for p in parts], orientation="h",
                                      marker_color=CONFIG_COLORS.get(cfg1)))
                tb.update_xaxes(title="Server time (ms)")
                tb.update_yaxes(autorange="reversed")
                ui.chart(ui.style_fig(tb, 200, legend=None))
            with st.expander("Raw transaction record"):
                st.json(row)
