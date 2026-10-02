import os

import streamlit as st

from webapp import data_loader as dl
from webapp import findings as fd
from webapp import ui

ui.page_header(
    "Post-quantum signature schedules for streaming LLM inference",
    "PQ-Shield wraps a real inference service in seven protection configurations — from no cryptography to "
    "hybrid X25519MLKEM768 key exchange with ML-DSA-65 signatures — and measures what post-quantum migration "
    "costs, in milliseconds and bytes, and what it buys against passive and active attackers. It is an "
    "application-layer emulation, not a TLS implementation.",
    eyebrow="PQ-Shield · measurement study",
)

# ---------------------------------------------------------------- headline numbers
manifest = dl.load_manifest()
cards = []
sdf = fd.streaming(manifest.get("streaming"))
if sdf is not None and not sdf.empty:
    pc = sdf[(sdf["config"] == "full_pqc") & (sdf["strategy"] == "per_chunk")
             & (sdf["max_tokens"] == sdf["max_tokens"].max())]["total_signature_bytes"].median()
    hc = sdf[(sdf["config"] == "full_pqc") & (sdf["strategy"] == "hash_chain")
             & (sdf["max_tokens"] == sdf["max_tokens"].max())]["total_signature_bytes"].median()
    cards.append({"label": "ML-DSA-65 signatures per 200-token stream", "value": f"{pc:,.0f} B",
                  "sub": f"signing every chunk, vs {hc:,.0f} B with one hash-chain signature", "color": "#2471a3"})
camp = fd.campaign_frame()
if camp is not None:
    att = camp[(camp["attack"] != "benign") & (camp["attack"] != "checkpoint_strip_v2client")]
    ben = camp[camp["attack"] == "benign"]
    cards.append({"label": "Stream attacks detected", "value": f"{att['detected'].sum() / att['n'].sum():.0%}",
                  "sub": f"{int(att['detected'].sum()):,} of {int(att['n'].sum()):,} static and adaptive attack trials; "
                         f"{int(ben['detected'].sum())} false rejections in {int(ben['n'].sum())} genuine streams",
                  "color": "#16a085"})
ks = dl.load_key_substitution()
if ks:
    sub_un = [r for r in ks if r["mode"] == "unauthenticated" and r["variant"].startswith("substitute")]
    sub_pin = [r for r in ks if r["mode"] == "pinned" and r["variant"].startswith("substitute")]
    cards.append({"label": "Key substitution vs. unauthenticated handshake",
                  "value": f"{sum(r['forged_response_accepted'] for r in sub_un):,} / {sum(r['n_valid'] for r in sub_un):,}",
                  "sub": f"forged responses accepted; with a pinned identity key "
                         f"{sum(r['accepted'] for r in sub_pin)} of {sum(r['n_valid'] for r in sub_pin):,}",
                  "color": "#c0392b"})
kat = dl._load_json(os.path.join(dl.VALIDATION_DIR, "nist_kat.json"))
if kat:
    s = kat["summary"]
    cards.append({"label": "NIST ACVP vectors reproduced", "value": f"{s['passed']} / {s['total_checks']}",
                  "sub": "ML-KEM-768 and ML-DSA-65, incl. key generation and signing byte for byte",
                  "color": "#6c3fa0"})
if cards:
    ui.kpi_cards(cards)

# ---------------------------------------------------------------- configurations
ui.section("Seven configurations",
           "Same inference service, same AES-256-GCM session layer; only the key exchange and the signature "
           "differ. Control-2RT makes the same two HTTP requests as a protected transaction with no cryptography, "
           "so protocol overhead and cryptographic overhead can be separated.")
ui.config_cards(["classical", "classical_ecdhe", "hybrid", "hybrid_kex", "full_pqc", "hybrid_kex_pq"])
st.caption("A: legacy worst case (RSA key generated per handshake) · A′: the realistic classical baseline · "
           "C′: added in revision and absent from the payload, network and session-reuse sweeps.")

# ---------------------------------------------------------------- where to go
ui.section("Explore")
c1, c2, c3 = st.columns(3)
with c1:
    with st.container(border=True):
        st.markdown("**Key findings**")
        st.caption("The paper's results, interactive: the signature-schedule dial, attack campaign, key "
                   "substitution, and a no-weights decision explorer.")
        st.page_link("views/key_findings.py", label="Open findings", icon=":material/insights:")
with c2:
    with st.container(border=True):
        st.markdown("**Live demo**")
        st.caption("Stream a real Llama response through any configuration and watch each chunk get verified "
                   "— or attack the stream on the wire.")
        st.page_link("views/live_demo.py", label="Open live demo", icon=":material/bolt:")
with c3:
    with st.container(border=True):
        st.markdown("**Threat lab**")
        st.caption("Harvest-now-decrypt-later exposure, tampering, sequence attacks, and key substitution "
                   "against a live server.")
        st.page_link("views/threat_lab.py", label="Open threat lab", icon=":material/security:")

# ---------------------------------------------------------------- environment
ui.section("Environment")
e1, e2, e3 = st.columns(3)
with e1:
    with st.container(border=True):
        st.markdown("**liboqs bindings**")
        if st.button("Run self-test", icon=":material/science:"):
            try:
                from crypto.oqs_adapter import verify_algorithms

                verify_algorithms()
                st.success("ML-KEM-768 and ML-DSA-65 round-trips passed.", icon=":material/check_circle:")
            except Exception as exc:
                st.error(f"Self-test failed: {exc}")
                st.caption("Run `bash scripts/install_oqs.sh` and set `PQ_SHIELD_OQS_LIB`.")
        else:
            st.caption("Checks that ML-KEM-768 and ML-DSA-65 work through the ctypes binding.")
with e2:
    with st.container(border=True):
        st.markdown("**Models**")
        clf = os.path.isfile(os.path.join(dl.REPO_ROOT, "model", "artifacts", "model.pkl"))
        llm = os.path.isfile(os.environ.get("PQ_SHIELD_LLAMA_MODEL_PATH", "") or "/nonexistent")
        st.markdown(f"{'✅' if clf else '⚪'} RandomForest classifier  \n{'✅' if llm else '⚪'} Llama-3.2-3B (GGUF)")
        if not clf:
            st.code("python -m model.train", language="bash")
with e3:
    with st.container(border=True):
        st.markdown("**Paper runs**")
        if manifest:
            from datetime import datetime

            try:
                when = datetime.fromisoformat(manifest.get("finished", "")).strftime("%-d %b %Y, %H:%M")
            except ValueError:
                when = manifest.get("finished", "—")
            st.markdown(f"Last run finished **{when}**")
            st.caption(f"{len(manifest.get('completed_steps', []))} experiment steps recorded in "
                       "`results/paper_runs.json`.")
        else:
            st.markdown("No manifest yet")
            st.caption("Run `python -m bench.paper_runs` to reproduce every experiment.")
