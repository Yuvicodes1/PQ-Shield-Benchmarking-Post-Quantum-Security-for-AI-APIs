import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from webapp.bootstrap import load_dotenv_if_needed

load_dotenv_if_needed()

import pandas as pd
import streamlit as st

from bench.orchestrator import REPO_ROOT, run_full_sweep

st.set_page_config(page_title="PQ-Shield — Benchmark Runner", page_icon="🚀", layout="wide")
st.title("🚀 Benchmark Runner")
st.caption(
    "Runs a real concurrency sweep using the same bench.orchestrator the CLI uses — each "
    "selected configuration's server is started fresh, swept, and stopped before the next one. "
    "This blocks the browser tab until finished; keep concurrency/repetitions modest for an "
    "interactive session, and use the CLI (`python -m bench.orchestrator`) for the full "
    "paper-scale matrix (10/100/1000 x 5 reps), which takes tens of minutes."
)

st.warning(
    "⚠️ High concurrency values on a resource-constrained machine can make individual requests "
    "queue for a long time (this is itself a valid, documented finding — see docs/DESIGN.md — but "
    "makes for a slow interactive demo). Start small.",
    icon="⚠️",
)

with st.form("sweep_form"):
    col1, col2 = st.columns(2)
    with col1:
        configs = st.multiselect(
            "Configurations",
            ["control", "classical", "hybrid", "full-pqc"],
            default=["control", "classical", "hybrid", "full-pqc"],
        )
        concurrency_choices = st.multiselect(
            "Concurrency levels",
            [1, 5, 10, 25, 50, 100, 250, 500, 1000],
            default=[5, 10],
        )
    with col2:
        repetitions = st.number_input("Repetitions per cell", min_value=1, max_value=5, value=1)
        requests_per_concurrency = st.number_input(
            "Requests per concurrency (requests = concurrency x this)", min_value=1, max_value=20, value=3
        )
        min_requests = st.number_input("Minimum requests per cell", min_value=5, max_value=200, value=15)

    submitted = st.form_submit_button("Run sweep", type="primary")

if submitted:
    if not configs or not concurrency_choices:
        st.error("Select at least one configuration and one concurrency level.")
    else:
        raw_dir = os.path.join(REPO_ROOT, "results", "raw")
        log_dir = os.path.join(REPO_ROOT, "results", "server_logs")
        progress_area = st.empty()
        progress_area.info(
            f"Running {len(configs)} configuration(s) x {len(concurrency_choices)} concurrency "
            f"level(s) x {repetitions} repetition(s)... this will take a while for larger settings."
        )
        with st.spinner("Sweeping..."):
            summaries = run_full_sweep(
                configs=configs,
                concurrency_levels=sorted(concurrency_choices),
                repetitions=int(repetitions),
                requests_per_concurrency=int(requests_per_concurrency),
                min_requests=int(min_requests),
                port=8000,
                raw_dir=raw_dir,
                log_dir=log_dir,
            )
        progress_area.success(f"Done — {len(summaries)} cells completed.")
        st.dataframe(pd.DataFrame(summaries), width='stretch')
        st.info("Go to the **Results Dashboard** page to see updated charts and statistics.")

st.divider()
st.subheader("Existing raw result files")
try:
    from webapp.data_loader import raw_file_inventory

    inv = raw_file_inventory()
    if inv.empty:
        st.info("No raw CSVs yet.")
    else:
        st.dataframe(inv, width='stretch', height=300)
except Exception as exc:
    st.error(f"Could not list results: {exc}")
