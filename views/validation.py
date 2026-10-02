import os

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from webapp import data_loader as dl
from webapp import ui

ui.page_header(
    "Validation",
    "Ground truth for the measurement instrument itself: do the post-quantum bindings reproduce NIST's official "
    "test vectors, does the streaming harness count signatures exactly as the analytic model says, and do the "
    "threat experiments agree with the threat model?",
    eyebrow="Evidence",
)


@st.cache_data(show_spinner=False)
def _kat():
    from validation.nist_kat import run_all

    return run_all()


ui.section("NIST ACVP known-answer tests",
           "Each vector's output is recomputed from its input and compared byte for byte. ML-DSA key generation and "
           "signing are reproduced by supplying the vector's 32 random bytes through liboqs's random-source hook.")
try:
    with st.spinner("Running 130 vectors…"):
        kat = _kat()
    s = kat["summary"]
    rows = [
        ("ML-KEM-768", "Key generation (FIPS 203 Alg. 16)", kat["ml_kem_768_keygen"], "byte-exact"),
        ("ML-KEM-768", "Encapsulation (Alg. 17)", kat["ml_kem_768_encap_decap"]["encapsulation"], "byte-exact"),
        ("ML-KEM-768", "Decapsulation incl. implicit rejection", kat["ml_kem_768_encap_decap"]["decapsulation"], "byte-exact"),
        ("ML-DSA-65", "Key generation from seed ξ (FIPS 204 Alg. 1)", kat.get("ml_dsa_65_keygen"), "byte-exact"),
        ("ML-DSA-65", "Signing, deterministic + hedged (Alg. 2)", kat.get("ml_dsa_65_siggen"), "byte-exact"),
        ("ML-DSA-65", "Signature verification (Alg. 3)", kat["ml_dsa_65_sigver"], "correct verdict"),
    ]
    l, r = st.columns([1, 2.2])
    with l:
        ui.kpi_cards([{"label": "Vectors passed", "value": f"{s['passed']} / {s['total_checks']}",
                       "sub": "all pass" if s["all_passed"] else "FAILURES", "color": "#16a085" if s["all_passed"] else "#c0392b"}])
    with r:
        st.dataframe(pd.DataFrame([{"Algorithm": a, "Test": t,
                                    "Passed": f"{d['passed']} / {d['total']}" if d else "—",
                                    "Rate": 100 * d["passed"] / d["total"] if d and d["total"] else None,
                                    "Basis": b} for a, t, d, b in rows]),
                     hide_index=True, width="stretch",
                     column_config={"Rate": st.column_config.ProgressColumn("Pass rate", min_value=0, max_value=100,
                                                                            format="%.0f%%")})
    with st.expander("Not testable through liboqs's public API"):
        for k, v in kat["not_achievable"].items():
            st.markdown(f"- **{k}** — {v}")
    st.caption("A correctness check of our bindings on these vectors, not ACVP certification.")
except Exception as exc:
    st.warning(f"Known-answer tests unavailable: {exc}")

ui.section("Streaming harness vs. the analytic model",
           "Signature counts and bytes follow from the strategy and the number of chunks "
           "(⌊n/k⌋ + 1 for a chain checkpointed every k). Signing time is bounded, not predicted: it depends on "
           "processor power state between chunks.")
manifest = dl.load_manifest()
from webapp import findings as fd

frames = [d for d in (fd.streaming(manifest.get("streaming")), fd.streaming(manifest.get("checkpoint"))) if d is not None]
if frames:
    allc = pd.concat(frames, ignore_index=True)
    allc["k"] = allc["checkpoint_interval"].fillna(0).astype(int) if "checkpoint_interval" in allc else 0
    allc["predicted"] = allc.apply(
        lambda r: 1 if r["strategy"] in ("buffer_and_sign",) or (r["strategy"] == "hash_chain" and r["k"] == 0)
        else (r["n_chunks"] + 1 if r["strategy"] == "per_chunk" else r["n_chunks"] // r["k"] + 1), axis=1)
    allc["match"] = allc["predicted"] == allc["n_signatures"]
    cells = allc.groupby(["config", "strategy", "k", "max_tokens"])["match"].all()
    ui.kpi_cards([
        {"label": "Streams checked", "value": f"{len(allc):,}"},
        {"label": "Signature count = model", "value": f"{int(allc['match'].sum()):,} / {len(allc):,}",
         "color": "#16a085" if allc["match"].all() else "#c0392b"},
        {"label": "Cells matching exactly", "value": f"{int(cells.sum())} / {len(cells)}"},
    ])
    cc = dl.load_contention_check()
    if cc is not None:
        st.caption("Per-signature time: see Key findings › Signing cost for the back-to-back vs. spaced diagnostic.")
else:
    ui.empty_state("No paper streaming runs found.")

ui.section("Threat model vs. experiments",
           "Two assumptions are checked against the threat experiments rather than assumed.")
from analysis.security_validation import validate_authenticity_near_term, validate_confidentiality_axis

c1, c2 = st.columns(2)
with c1:
    with st.container(border=True):
        st.markdown("**Confidentiality** — recorded key exchange decryptable only for RSA / X25519")
        warnings = validate_confidentiality_axis(dl.load_hndl_summaries())
        if not warnings:
            st.success("Every HNDL capture on disk agrees with the threat model.", icon=":material/check_circle:")
        for w in warnings:
            st.warning(w)
with c2:
    with st.container(border=True):
        st.markdown("**Authenticity, near term** — tampered signatures rejected everywhere")
        res = validate_authenticity_near_term(dl.load_mitm_summaries())
        if res["all_near_100pct"]:
            st.success(res["note"], icon=":material/check_circle:")
        else:
            st.warning(res["note"])
