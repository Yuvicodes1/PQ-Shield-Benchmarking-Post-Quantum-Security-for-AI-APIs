import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from webapp.bootstrap import load_dotenv_if_needed

load_dotenv_if_needed()

import streamlit as st

from webapp import data_loader as dl

st.set_page_config(page_title="PQ-Shield — Cryptographic Validation", page_icon="🔬", layout="wide")
st.title("🔬 Cryptographic Validation")
st.caption(
    "Ground-truth checks, not benchmark results: do PQ-Shield's own liboqs bindings match NIST's "
    "official test vectors, and does the streaming signature-cost harness measure exactly what "
    "the signing strategies' own arithmetic says it should? Independent of any run selector on the "
    "Results Dashboard -- these validate the *measurement instrument* itself, not a specific "
    "sweep's results, so the streaming check below always uses every streaming run ever collected."
)

vc1, vc2 = st.columns(2)

with vc1:
    st.markdown("**NIST ACVP Known-Answer Tests** (ML-KEM-768 / ML-DSA-65 vs. NIST's own vectors)")
    try:
        from validation.nist_kat import run_all as run_nist_kat

        with st.spinner("Running KAT vectors..."):
            kat_results = run_nist_kat()
        kat_summary = kat_results["summary"]
        k1, k2 = st.columns(2)
        k1.metric("Vectors passed", f"{kat_summary['passed']}/{kat_summary['total_checks']}")
        k2.metric("All pass?", "✅ Yes" if kat_summary["all_passed"] else "❌ No")
        st.dataframe(
            [
                {"check": "ML-KEM-768 keyGen", "passed": kat_results["ml_kem_768_keygen"]["passed"],
                 "total": kat_results["ml_kem_768_keygen"]["total"]},
                {"check": "ML-KEM-768 encapsulation", "passed": kat_results["ml_kem_768_encap_decap"]["encapsulation"]["passed"],
                 "total": kat_results["ml_kem_768_encap_decap"]["encapsulation"]["total"]},
                {"check": "ML-KEM-768 decapsulation", "passed": kat_results["ml_kem_768_encap_decap"]["decapsulation"]["passed"],
                 "total": kat_results["ml_kem_768_encap_decap"]["decapsulation"]["total"]},
                {"check": "ML-DSA-65 signature verification", "passed": kat_results["ml_dsa_65_sigver"]["passed"],
                 "total": kat_results["ml_dsa_65_sigver"]["total"]},
            ],
            width='stretch', hide_index=True,
        )
        with st.expander("Not achievable through liboqs's public API (documented, not skipped)"):
            st.json(kat_results["not_achievable"])
        with st.expander("Full KAT results JSON"):
            st.json(kat_results)
    except Exception as exc:
        st.warning(f"NIST KAT check unavailable: {exc}")

with vc2:
    st.markdown("**Streaming Signature-Cost Model Validation** (measured vs. predicted from primitive costs)")
    all_streaming_df = dl.load_streaming_df()  # every streaming run ever collected
    primitive_bench_path = os.path.join(dl.REPO_ROOT, "results", "validation", "primitive_bench.json")
    if all_streaming_df is None or all_streaming_df.empty:
        st.info("No streaming sweep data yet -- see the streaming sweep tab in Benchmark Runner.")
    elif not os.path.isfile(primitive_bench_path):
        st.info(
            f"No `{os.path.relpath(primitive_bench_path, dl.REPO_ROOT)}` yet -- run "
            "`python -m validation.primitive_bench --output results/validation/primitive_bench.json` first."
        )
    else:
        try:
            from analysis.streaming_model_validation import run_validation as run_streaming_model_validation

            with st.spinner("Validating measured signature bytes/timing against the analytical model..."):
                mv = run_streaming_model_validation(dl.STREAMING_DIR, primitive_bench_path)
            mvs = mv["summary"]
            mv1, mv2, mv3 = st.columns(3)
            mv1.metric("Bytes: exact/in-range", f"{mvs['bytes_ok']}/{mvs['validated_rows']}",
                       delta="ALL OK" if mvs["bytes_all_ok"] else "mismatches", delta_color="off")
            mv2.metric("Timing (warm-loop baseline)", f"{mvs['timing_ok']}/{mvs['validated_rows']}")
            mv3.metric("Timing (best applicable baseline)", f"{mvs['timing_ok_best']}/{mvs['validated_rows']}")
            st.dataframe(mv["per_group"], width='stretch', hide_index=True)
            st.caption(
                "'Best applicable baseline' uses a cold-start-process correction for "
                "`buffer_and_sign` (see docs/STREAMING.md section 9 for why ECDSA specifically "
                "needs one and ML-DSA-65 doesn't) and the ordinary warm-loop mean elsewhere. "
                "Byte agreement is the strongest, fully-validated claim regardless of the timing "
                "baseline used."
            )
            with st.expander("Full validation results JSON (per-row detail)"):
                st.json(mv)
        except Exception as exc:
            st.warning(f"Streaming model validation unavailable: {exc}")

# ---------------------------------------------------------------------------
# Security-assumption validation -- a different kind of ground-truth check
# from the two above: not "does the crypto implementation match a spec",
# but "does the Trade-off Matrix's categorical SECURITY_SCORES mapping
# (analysis/tradeoff_matrix.py) actually agree with what the live Threat
# Scenarios experiments measured?" See analysis/security_validation.py.
# ---------------------------------------------------------------------------
st.divider()
st.subheader("Security-Score Assumption Validation")
st.caption(
    "The trade-off matrix's SECURITY_SCORES ordinal mapping asserts two things: classical's "
    "key-establishment is decryptable under a future CRQC (RSA) while hybrid/full_pqc's isn't "
    "(ML-KEM-768), and near-term signature-tamper detection is uniformly high across configs -- "
    "which is *why* authenticity is scored as a categorical future-forgery property rather than a "
    "detection-rate one. Both are checked here against real Threat Scenarios results, not assumed."
)

sv1, sv2 = st.columns(2)

with sv1:
    st.markdown("**Confidentiality axis vs. HNDL captures**")
    from analysis.security_validation import validate_authenticity_near_term, validate_confidentiality_axis

    conf_warnings = validate_confidentiality_axis(dl.load_hndl_summaries())
    if not conf_warnings:
        st.success("✅ Every config with an HNDL capture on disk agrees with SECURITY_SCORES' "
                   "confidentiality assumption.")
    else:
        for w in conf_warnings:
            st.warning(w)
    st.caption("Run the HNDL tab on the **🛡️ Threat Scenarios** page to add or refresh a config's capture.")

with sv2:
    st.markdown("**Authenticity axis vs. MITM signature-tamper detection**")
    auth_result = validate_authenticity_near_term(dl.load_mitm_summaries())
    if auth_result["per_config_detection_rate"]:
        st.dataframe(
            [{"config": c, "detection_rate": r} for c, r in auth_result["per_config_detection_rate"].items()],
            width='stretch', hide_index=True,
        )
    if auth_result["all_near_100pct"]:
        st.success(f"✅ {auth_result['note']}")
    else:
        st.warning(auth_result["note"])
    st.caption("Run the MITM tab (tamper target = signature) on the **🛡️ Threat Scenarios** page "
               "to add or refresh a config's detection rate.")
