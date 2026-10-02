import asyncio
import json
import os
import time

import httpx
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from webapp import data_loader as dl
from webapp import demo_transaction, server_manager, ui
from webapp.colors import CONFIG_COLORS

ui.page_header(
    "Threat lab",
    "Saved results and live runs for each adversary in the threat model: a passive recorder waiting for a "
    "quantum computer, an attacker who tampers with or rearranges records, and one who substitutes keys in an "
    "unauthenticated handshake.",
    eyebrow="Evidence",
)

PROTECTED = ui.PROTECTED

t_hndl, t_tamper, t_stream, t_keysub = st.tabs([
    ":material/inventory_2: Harvest now, decrypt later", ":material/edit_off: Tampering",
    ":material/swap_horiz: Stream integrity", ":material/key_off: Key substitution",
])


def _save(path: str, obj) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)


# ============================================================================ HNDL
with t_hndl:
    st.markdown("A passive adversary records every byte of a protected session and waits for a quantum computer. "
                "What becomes readable depends only on whether the recorded key exchange can be broken: RSA and "
                "X25519 can, ML-KEM-768 and X25519MLKEM768 cannot (under known attacks). The figures count "
                "bytes, not information content.")
    single = sorted(dl.load_hndl_summaries(), key=lambda s: PROTECTED.index(s["config"]) if s["config"] in PROTECTED else 99)
    streams = dl.load_streaming_hndl_summaries()
    l, r = st.columns(2)
    with l:
        ui.section("One transaction", "Bytes captured, by component")
        if single:
            fig = go.Figure()
            for comp, key, color in (("Key-exchange blob", "kex_bytes_per_request", "#2f5d8a"),
                                     ("Signature", "signature_bytes_per_request", "#c9822b")):
                fig.add_trace(go.Bar(y=[ui.label(s["config"]) for s in single], x=[s.get(key, 0) for s in single],
                                     name=comp, orientation="h", marker_color=color))
            fig.add_trace(go.Bar(y=[ui.label(s["config"]) for s in single],
                                 x=[s["bytes_per_request_mean"] - s.get("kex_bytes_per_request", 0)
                                    - s.get("signature_bytes_per_request", 0) for s in single],
                                 name="Ciphertext", orientation="h", marker_color="#9aa5b1"))
            fig.update_layout(barmode="stack", yaxis=dict(autorange="reversed"))
            fig.update_xaxes(title="Bytes per transaction")
            ui.chart(ui.style_fig(fig, 320))
            st.caption("Decryptable by a future quantum computer: "
                       + ", ".join(ui.SHORT[s["config"]] for s in single if s.get("kex_decryptable_under_future_crqc"))
                       + ". None of the ML-KEM configurations.")
        else:
            ui.empty_state("No single-transaction captures yet.")
    with r:
        ui.section("Streamed responses", "Bytes a future quantum computer could decrypt, by response length")
        if streams:
            fig = go.Figure()
            for s in sorted(streams, key=lambda s: PROTECTED.index(s["config"]) if s["config"] in PROTECTED else 99):
                fig.add_trace(go.Scatter(x=s.get("max_tokens_values", []),
                                         y=s.get("decryptable_bytes_under_future_crqc_by_length", []),
                                         mode="lines+markers", name=ui.SHORT[s["config"]],
                                         line=dict(color=CONFIG_COLORS.get(s["config"]))))
            fig.update_xaxes(title="Response length (max tokens)")
            fig.update_yaxes(title="Decryptable bytes")
            ui.chart(ui.style_fig(fig, 320))
            st.caption("Linear in length under classical key exchange (≈11.4 B per token, 5.8 B of it plaintext, for "
                       "this model and tokenizer); zero for every ML-KEM configuration.")
        else:
            ui.empty_state("No streaming HNDL results yet.")

    with st.expander("Run a capture", icon=":material/play_arrow:"):
        c1, c2, c3 = st.columns([1.4, 1, 1])
        cfg = c1.selectbox("Configuration", PROTECTED, format_func=ui.label, key="hndl_cfg")
        n = c2.number_input("Transactions", 10, 2000, 200, step=10, key="hndl_n")
        c3.write("")
        if c3.button("Capture", type="primary", key="hndl_go"):
            from threats.hndl_capture import capture, summarize

            with st.spinner("Capturing…"):
                base = server_manager.ensure_server(cfg)
                res = summarize(asyncio.run(capture(cfg, base, int(n))), cfg)
            m = st.columns(3)
            m[0].metric("Bytes per transaction", f"{res['bytes_per_request_mean']:.0f}")
            m[1].metric("Per 1,000 transactions", f"{res['projected_bytes_per_1000_requests']:,.0f}")
            m[2].metric("Decryptable later?", "Yes" if res["kex_decryptable_under_future_crqc"] else "No")
            _save(os.path.join(dl.HNDL_DIR, f"{cfg}-hndl-summary.json"), res)

# ============================================================================ tampering
with t_tamper:
    st.markdown("Flip one bit of a response in transit. The AES-GCM tag catches a ciphertext change before the "
                "signature is even checked; a signature change is caught by verification. This shows the checks "
                "work and are cheap — not that the protocol resists a man-in-the-middle (see Key substitution).")
    mitm = dl.load_mitm_summaries()
    if mitm:
        df = pd.DataFrame(mitm)
        df = df[df["config"].isin(PROTECTED)]
        df["t"] = df.get("detection_ms_median", df.get("detection_ms_mean")) * 1000
        fig = go.Figure()
        for target, color in (("ciphertext", "#9aa5b1"), ("signature", "#c9822b")):
            g = df[df["tamper_target"] == target].set_index("config").reindex([c for c in PROTECTED if c in set(df["config"])])
            fig.add_trace(go.Bar(x=[ui.SHORT[c] for c in g.index], y=g["t"], name=f"{target.capitalize()} bit flipped",
                                 marker_color=color,
                                 text=[f"{v:.0f} µs" for v in g["t"]], textposition="outside", cliponaxis=False))
        fig.update_yaxes(title="Time of the rejecting check (µs, median)")
        fig.update_layout(barmode="group")
        ui.chart(ui.style_fig(fig, 340))
        st.caption(f"Every tampered response was rejected ({int(df['n_requests'].sum()):,} trials).")
    with st.expander("Run a tampering demo", icon=":material/play_arrow:"):
        c1, c2, c3, c4 = st.columns([1.4, 1, 1, 1])
        cfg = c1.selectbox("Configuration", PROTECTED, format_func=ui.label, key="mitm_cfg")
        target = c2.selectbox("Flip a bit in", ["ciphertext", "signature"], key="mitm_target")
        n = c3.number_input("Trials", 5, 200, 25, step=5, key="mitm_n")
        c4.write("")
        if c4.button("Run", type="primary", key="mitm_go"):
            base = server_manager.ensure_server(cfg)
            features, _, _ = demo_transaction.get_sample(0)

            async def trials():
                return [await demo_transaction.run_secure_transaction(base, cfg, features, tamper_target=target)
                        for _ in range(int(n))]

            with st.spinner("Running…"):
                rows = asyncio.run(trials())
            det = sum(1 for r in rows if r.get("valid_signature") is False or r.get("decryption_ok") is False)
            st.metric("Rejected", f"{det} / {len(rows)}")

# ============================================================================ stream integrity
with t_stream:
    st.markdown("Rearrange validly protected records without forging any. Binding role, session and position into "
                "every signed message, plus a signed end record, makes every tested attack detectable — but "
                "detection arrives only with a signature, so the checkpoint interval decides how much unverified "
                "text the user has already seen.")
    doc = dl.load_campaign()
    if doc:
        df = pd.DataFrame(doc["rows"])
        df["k"] = df["checkpoint_interval"].fillna(0).astype(int)
        att = df[(df["attack"] != "benign") & (df["strategy"] == "hash_chain")]
        names = {"drop": "Drop", "reorder": "Reorder", "duplicate": "Duplicate", "truncate": "Truncate",
                 "drop_after_ckpt": "Drop after checkpoint"}
        fig = go.Figure()
        ks = [2, 5, 10, 0]
        for a, name in names.items():
            ys = []
            for k in ks:
                g = att[(att["attack"] == a) & (att["k"] == k)]
                ys.append((g["unverified_at_detection_mean"] * g["n"]).sum() / g["n"].sum() * 5 if g["n"].sum() else None)
            fig.add_trace(go.Scatter(x=["k=2", "k=5", "k=10", "no checkpoints"], y=ys, mode="lines+markers", name=name))
        fig.update_yaxes(title="Unverified tokens shown when caught")
        ui.chart(ui.style_fig(fig, 340))
        st.caption(f"Campaign: {doc['trials']} trials per configuration and cell, pooled over "
                   f"{df['config'].nunique()} configurations ({doc['max_tokens']}-token streams). The full matrix is on "
                   "the Key findings page.")
    with st.expander("Run a sequence attack", icon=":material/play_arrow:"):
        c1, c2, c3 = st.columns(3)
        cfg = c1.selectbox("Configuration", PROTECTED, format_func=ui.label, key="sm_cfg")
        strategy = c2.selectbox("Strategy", ["per_chunk", "hash_chain"], key="sm_strategy")
        attack = c3.selectbox("Attack", ["drop", "reorder", "duplicate", "replay", "truncate"], key="sm_attack")
        c4, c5, c6 = st.columns(3)
        k = c4.select_slider("Checkpoint every k", ["off", 2, 3, 5], value="off", key="sm_k",
                             disabled=strategy != "hash_chain")
        n = c5.number_input("Trials", 3, 100, 10, key="sm_n")
        c6.write("")
        if c6.button("Run", type="primary", key="sm_go"):
            from threats.streaming_mitm_experiment import run_trial, summarize

            base = server_manager.ensure_server(cfg)
            kk = None if (k == "off" or strategy != "hash_chain") else int(k)

            async def go_trials():
                out, foreign = [], None
                async with httpx.AsyncClient(timeout=60.0) as client:
                    for _ in range(int(n)):
                        row = await run_trial(client, base, cfg, strategy, attack, checkpoint_interval=kk,
                                              foreign_chunks=foreign)
                        foreign = row.pop("foreign_chunks", None) or foreign
                        out.append(row)
                return out

            with st.spinner(f"Running {n} trials…"):
                rows = asyncio.run(go_trials())
            s = summarize(rows, cfg, strategy, attack)
            if s["detection_rate"] is None:
                st.warning("Every trial errored — try longer streams.")
            else:
                m = st.columns(3)
                m[0].metric("Detected", f"{s['detection_rate']:.0%}")
                m[1].metric("Caught before the stream ended", f"{s['mid_stream_detection_rate']:.0%}")
                m[2].metric("Stream delivered first", f"{s['fraction_delivered_before_detection_mean']:.0%}")

# ============================================================================ key substitution
with t_keysub:
    st.markdown("An attacker in the middle replaces the server's key shares and signing key with its own, reads "
                "the request, and signs a forged response. No AEAD or signature check can stop this — the client "
                "verifies under whatever key it received — unless the server signs the handshake transcript with "
                "an identity key the client already trusts.")
    ks = dl.load_key_substitution()
    if ks:
        kdf = pd.DataFrame(ks)
        variants = [("benign", "No attack"), ("substitute", "Substitute keys"),
                    ("substitute_resign", "Substitute + re-sign"), ("relay_tamper", "Relay + bit flip")]
        fig = go.Figure()
        for mode, name, color in (("unauthenticated", "Unauthenticated", "#c0392b"), ("pinned", "Pinned identity key", "#16a085")):
            ys = []
            for v, _ in variants:
                g = kdf[(kdf["mode"] == mode) & (kdf["variant"] == v)]
                ys.append(100 * g["forged_response_accepted"].sum() / g["n_valid"].sum() if v.startswith("substitute")
                          else 100 * g["accepted"].sum() / g["n_valid"].sum())
            fig.add_trace(go.Bar(x=[n for _, n in variants], y=ys, name=name, marker_color=color,
                                 text=[f"{y:.0f}%" for y in ys], textposition="outside", cliponaxis=False))
        fig.update_yaxes(title="Accepted by the client (%)", range=[0, 115])
        fig.update_layout(barmode="group")
        ui.chart(ui.style_fig(fig, 330))
        st.caption("For substitution attacks the bar is the share of forged responses accepted; otherwise the share "
                   f"of responses accepted. {kdf['config'].nunique()} configurations × 300 trials each; results were "
                   "identical for post-quantum and classical configurations.")
    with st.expander("Run against a live server", icon=":material/play_arrow:"):
        c1, c2, c3, c4 = st.columns([1.4, 1.2, 1, 1])
        cfg = c1.selectbox("Configuration", PROTECTED, index=4, format_func=ui.label, key="ks_cfg")
        variant = c2.selectbox("Attack", ["substitute", "substitute_resign", "relay_tamper", "benign"],
                               format_func=lambda v: dict(variants if ks else []).get(v, v), key="ks_var")
        n = c3.number_input("Trials", 1, 100, 10, key="ks_n")
        c4.write("")
        if c4.button("Run", type="primary", key="ks_go"):
            from api.secure_client import fetch_identity
            from crypto.handshake_auth import IdentityKey
            from threats.key_substitution import _trial

            base = server_manager.ensure_server(cfg)

            async def go_ks():
                out = {}
                async with httpx.AsyncClient(timeout=30.0) as http:
                    pinned = await fetch_identity(http, base)
                    attacker_id = IdentityKey.generate(pinned["algorithm"])
                    for mode in ("unauthenticated", "pinned"):
                        out[mode] = [await _trial(http, base, cfg, variant, mode, pinned, attacker_id)
                                     for _ in range(int(n))]
                return out

            t0 = time.perf_counter()
            with st.spinner("Running…"):
                res = asyncio.run(go_ks())
            cols = st.columns(2)
            for col, mode, title in ((cols[0], "unauthenticated", "Unauthenticated client"),
                                     (cols[1], "pinned", "Client with pinned identity key")):
                rows = res[mode]
                with col:
                    with st.container(border=True):
                        st.markdown(f"**{title}**")
                        acc = sum(r["client_accepted"] for r in rows)
                        forged = sum(r["forged_response_accepted"] for r in rows)
                        read = sum(r["attacker_read_request"] for r in rows)
                        if forged:
                            st.error(f"Attacker read {read}/{len(rows)} requests; {forged} forged predictions accepted",
                                     icon=":material/gpp_bad:")
                        elif acc == len(rows) and variant == "benign":
                            st.success(f"All {acc} genuine responses accepted", icon=":material/verified_user:")
                        else:
                            where = {r["rejected_at"] for r in rows if r["rejected_at"]}
                            st.success(f"Attack stopped in {len(rows) - acc}/{len(rows)} trials "
                                       f"(rejected at: {', '.join(where) or '—'})", icon=":material/shield:")
            st.caption(f"{time.perf_counter() - t0:.1f} s")
