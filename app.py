import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from webapp.bootstrap import load_dotenv_if_needed

load_dotenv_if_needed()

import streamlit as st

st.set_page_config(page_title="PQ-Shield", page_icon="🛡️", layout="wide")

st.title("🛡️ PQ-Shield")
st.caption("Security-Performance Benchmarking of PQC Algorithms for AI API Protection")

st.markdown(
    """
PQ-Shield wraps a real-time FastAPI digit-classifier inference API in three
cryptographic configurations and measures the operational cost of migrating
to NIST post-quantum cryptography (ML-KEM-768 / FIPS 203, ML-DSA-65 / FIPS 204),
under concurrency and two adversarial threat scenarios.

Use the pages in the sidebar to:
- **Live Demo** — send a single request through any configuration in real time and see the full timing/byte breakdown, including a live tamper-detection demo.
- **Benchmark Runner** — run a scoped concurrency sweep directly from the browser.
- **Results Dashboard** — explore whatever benchmark data currently exists on disk, with an interactive security/performance trade-off matrix.
- **Threat Scenarios** — HNDL storage-growth and MITM tamper-detection results, or run either experiment on demand.
"""
)

st.divider()
st.subheader("Environment status")

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("**liboqs / crypto self-test**")
    if st.button("Run self-test"):
        try:
            from crypto.oqs_adapter import verify_algorithms

            result = verify_algorithms()
            st.success("ML-KEM-768 and ML-DSA-65 round-trips passed.")
            st.json(result)
        except Exception as exc:
            st.error(f"Self-test failed: {exc}")
            st.info(
                "Run `bash scripts/install_oqs.sh` and set `PQ_SHIELD_OQS_LIB` "
                "to the built liboqs.so path."
            )

with col2:
    st.markdown("**Model artifact**")
    model_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "model", "artifacts", "model.pkl"
    )
    if os.path.isfile(model_path):
        st.success("model.pkl found.")
    else:
        st.warning("No model artifact yet.")
        st.code("python -m model.train", language="bash")

with col3:
    st.markdown("**Benchmark data**")
    try:
        from webapp.data_loader import load_raw_df

        df = load_raw_df()
        if df is None:
            st.warning("No results/raw/*.csv found yet.")
            st.caption("Use the Benchmark Runner page, or run bench.orchestrator from the CLI.")
        else:
            n_configs = df["config"].nunique()
            st.success(f"{len(df):,} requests across {n_configs} configuration(s).")
    except Exception as exc:
        st.error(f"Could not load results: {exc}")

st.divider()
st.subheader("Configurations")
st.table(
    {
        "Configuration": ["Control", "A — Classical", "B — Hybrid", "C — Full PQC"],
        "Key establishment": ["none", "RSA-2048-OAEP", "ML-KEM-768 (FIPS 203)", "ML-KEM-768 (FIPS 203)"],
        "Response signature": ["none", "ECDSA P-256", "ECDSA P-256", "ML-DSA-65 (FIPS 204)"],
    }
)

st.caption(
    "See `docs/DESIGN.md` in the repository for the full protocol design, "
    "hypotheses (H1–H4), and statistical methodology."
)
