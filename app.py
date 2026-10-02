"""PQ-Shield dashboard entry point:  streamlit run app.py

Sets up the environment once, then routes to the pages in views/ with
grouped sidebar navigation.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from webapp.bootstrap import load_dotenv_if_needed

load_dotenv_if_needed()

import streamlit as st

st.set_page_config(page_title="PQ-Shield", page_icon=":material/shield_lock:", layout="wide",
                   initial_sidebar_state="expanded")

pages = {
    "Overview": [
        st.Page("views/home.py", title="Home", icon=":material/shield_lock:", default=True),
        st.Page("views/key_findings.py", title="Key findings", icon=":material/insights:"),
    ],
    "Interactive": [
        st.Page("views/live_demo.py", title="Live demo", icon=":material/bolt:"),
        st.Page("views/benchmark_runner.py", title="Benchmark runner", icon=":material/play_circle:"),
    ],
    "Evidence": [
        st.Page("views/results_explorer.py", title="Results explorer", icon=":material/monitoring:"),
        st.Page("views/threat_lab.py", title="Threat lab", icon=":material/security:"),
        st.Page("views/validation.py", title="Validation", icon=":material/verified:"),
    ],
}

from webapp.ui import theme_toggle

with st.sidebar:
    theme_toggle([p.url_path for group in pages.values() for p in group])
    st.caption("Post-quantum signature schedules for streaming LLM inference")

st.navigation(pages).run()
