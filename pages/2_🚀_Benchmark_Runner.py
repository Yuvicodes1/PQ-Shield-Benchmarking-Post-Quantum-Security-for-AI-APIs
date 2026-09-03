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

tab_concurrency, tab_streaming = st.tabs(["Concurrency Sweep", "🌊 Streaming Sweep"])

# =============================================================================
# Tab 1: the existing concurrency x repetition x configuration sweep
# =============================================================================
with tab_concurrency:
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
            run_id = summaries[0]["run_id"] if summaries else None
            if run_id:
                st.caption(
                    f"run_id = `{run_id}` — the Results Dashboard defaults to showing just this "
                    "run; switch its 'Data source' selector to see older runs or everything combined."
                )
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

# =============================================================================
# Tab 2: the streaming (SSE signing-strategy) sweep
# =============================================================================
with tab_streaming:
    st.caption(
        "Runs bench.streaming_runner's sweep: for each configuration x signing strategy x response "
        "length x chunk size, sends one streaming prompt and records time-to-first-token, total "
        "signature bytes, and full chunk-level verification — the experiment behind the numbers in "
        "`docs/STREAMING.md`. Unlike the concurrency sweep, this is deliberately one transaction at a "
        "time (response size and signing strategy are the variables under study here, not load)."
    )

    llama_model_path = os.environ.get("PQ_SHIELD_LLAMA_MODEL_PATH", "")
    try:
        import llama_cpp  # noqa: F401
        llama_cpp_installed = True
    except ImportError:
        llama_cpp_installed = False
    real_backend_available = llama_cpp_installed and os.path.isfile(llama_model_path)

    backend_choice = st.radio(
        "Token generation backend",
        ["Synthetic (fast, no setup)", "Real model — llama.cpp"],
        help=(
            "Synthetic: deterministic, simulated timing, zero dependencies — good for checking the "
            "protocol/signature-overhead numbers quickly. Real: genuine LLM generation via "
            "model/streaming_backends/llama_cpp_backend.py — realistic time-to-first-token, but each "
            "transaction takes as long as real generation does (seconds, not milliseconds), and this "
            "sweep blocks the browser tab until it's done. See docs/STREAMING.md 'Setting up a real "
            "model backend' to enable this."
        ),
    )
    use_real_backend = backend_choice.startswith("Real")

    if use_real_backend and not real_backend_available:
        reason = (
            "llama-cpp-python is not installed" if not llama_cpp_installed
            else f"PQ_SHIELD_LLAMA_MODEL_PATH ({llama_model_path or 'not set'}) does not point to a file"
        )
        st.error(f"Real backend selected but unavailable: {reason}. Falling back to synthetic.")
        use_real_backend = False
    elif use_real_backend:
        st.info(f"Using real model: `{os.path.basename(llama_model_path)}`")

    synthetic_tokens_per_sec = None
    if not use_real_backend:
        synthetic_tokens_per_sec = st.slider(
            "Synthetic tokens/sec (higher = faster demo, less realistic absolute timing)",
            10, 1000, 300,
            help="Only affects the synthetic backend's simulated delay between tokens.",
        )

    with st.form("streaming_sweep_form"):
        col1, col2 = st.columns(2)
        with col1:
            stream_configs = st.multiselect(
                "Configurations", ["classical", "hybrid", "full-pqc"],
                default=["classical", "hybrid", "full-pqc"],
            )
            strategies = st.multiselect(
                "Signing strategies", ["buffer_and_sign", "per_chunk", "hash_chain"],
                default=["buffer_and_sign", "per_chunk", "hash_chain"],
            )
        with col2:
            max_tokens_values = st.multiselect(
                "Response lengths (max tokens)", [20, 50, 100, 200, 500],
                default=[50, 200],
            )
            chunk_size_values = st.multiselect(
                "Chunk sizes (tokens per signed/hashed unit)", [1, 5, 10, 20],
                default=[5],
            )
            stream_repetitions = st.number_input(
                "Repetitions per combination", min_value=1, max_value=5, value=1
            )

        n_combos = len(stream_configs) * len(strategies) * len(max_tokens_values) * len(chunk_size_values) * int(stream_repetitions)
        st.caption(f"{n_combos} streaming transaction(s) total.")
        if use_real_backend and n_combos > 20:
            st.warning(
                f"⚠️ {n_combos} transactions against the real backend could take a long time "
                "(each one is genuine generation, easily several seconds). Consider fewer combinations.",
                icon="⚠️",
            )

        stream_submitted = st.form_submit_button("Run streaming sweep", type="primary")

    if stream_submitted:
        if not (stream_configs and strategies and max_tokens_values and chunk_size_values):
            st.error("Select at least one configuration, strategy, response length, and chunk size.")
        else:
            if use_real_backend:
                os.environ["PQ_SHIELD_STREAMING_BACKEND"] = "llama_cpp"
            else:
                os.environ["PQ_SHIELD_STREAMING_BACKEND"] = "synthetic"
                os.environ["PQ_SHIELD_SYNTHETIC_TOKENS_PER_SEC"] = str(synthetic_tokens_per_sec)

            from bench.streaming_runner import run_sweep as run_streaming_sweep

            output_dir = os.path.join(REPO_ROOT, "results", "streaming")
            log_dir = os.path.join(REPO_ROOT, "results", "server_logs")
            progress_area = st.empty()
            progress_area.info(f"Running {n_combos} streaming transaction(s)... this will take a while.")
            with st.spinner("Streaming sweep in progress..."):
                stream_rows = run_streaming_sweep(
                    configs=stream_configs,
                    strategies=strategies,
                    max_tokens_values=sorted(max_tokens_values),
                    chunk_size_values=sorted(chunk_size_values),
                    repetitions=int(stream_repetitions),
                    port=8000,
                    output_dir=output_dir,
                    log_dir=log_dir,
                )
            n_errors = sum(1 for r in stream_rows if r.get("error"))
            if n_errors:
                progress_area.warning(f"Done — {len(stream_rows)} transactions, {n_errors} error(s).")
            else:
                progress_area.success(f"Done — {len(stream_rows)} transactions, all verified.")
            st.dataframe(pd.DataFrame(stream_rows), width='stretch')
            st.info(
                "Results written to `results/streaming/*.csv`. Run "
                "`python -m analysis.streaming_analysis` for the summarized comparison, or check "
                "the file inventory below."
            )

    st.divider()
    st.subheader("Existing streaming result files")
    try:
        from webapp.data_loader import streaming_file_inventory

        stream_inv = streaming_file_inventory()
        if stream_inv.empty:
            st.info("No streaming sweep CSVs yet.")
        else:
            st.dataframe(stream_inv, width='stretch', height=200)
    except Exception as exc:
        st.error(f"Could not list streaming results: {exc}")
