import os

import pandas as pd
import streamlit as st

from bench.orchestrator import REPO_ROOT, run_full_sweep
from webapp import data_loader as dl
from webapp import ui

ui.page_header(
    "Benchmark runner",
    "Run a scoped sweep from the browser with the same orchestrator the paper uses. Each configuration's server "
    "is started fresh, swept, and stopped. Keep sweeps small here; reproduce the paper with "
    "<code>python -m bench.paper_runs</code>.",
    eyebrow="Interactive",
)

ALL = ["control", "control-2rt", "classical", "classical-ecdhe", "hybrid", "hybrid-kex", "full-pqc", "hybrid-kex-pq"]
PROT = ALL[2:]
lab = lambda k: ui.label(dl.HYPHEN_TO_CRYPTO[k])

t_conc, t_stream = st.tabs([":material/speed: Concurrency sweep", ":material/stream: Streaming sweep"])

with t_conc:
    with st.form("conc"):
        c1, c2 = st.columns(2)
        with c1:
            configs = st.multiselect("Configurations", ALL, default=["control-2rt", "classical-ecdhe", "hybrid", "full-pqc"],
                                     format_func=lab)
            levels = st.pills("Concurrency levels", [1, 5, 10, 25, 50, 100, 250, 500, 1000], selection_mode="multi",
                              default=[10])
            auth = st.toggle("Authenticated handshake", value=False,
                             help="Servers sign each handshake transcript with an identity key; clients pin it and "
                                  "verify (crypto/handshake_auth.py).")
        with c2:
            reps = st.number_input("Repetitions per cell", 1, 10, 2)
            rpc = st.number_input("Requests per connection", 1, 20, 5)
            min_req = st.number_input("Minimum requests per cell", 5, 500, 50)
        n_cells = len(configs) * len(levels or []) * int(reps)
        st.caption(f"{n_cells} cells. High concurrency on one machine mostly measures contention.")
        go = st.form_submit_button("Run sweep", type="primary", icon=":material/play_arrow:")
    if go:
        if not configs or not levels:
            st.error("Pick at least one configuration and one concurrency level.")
        else:
            with st.status(f"Running {n_cells} cells…", expanded=False) as status:
                summaries = run_full_sweep(configs=configs, concurrency_levels=sorted(levels), repetitions=int(reps),
                                           requests_per_concurrency=int(rpc), min_requests=int(min_req), port=8000,
                                           raw_dir=os.path.join(REPO_ROOT, "results", "raw"),
                                           log_dir=os.path.join(REPO_ROOT, "results", "server_logs"),
                                           auth_handshake=auth)
                status.update(label=f"Done — {len(summaries)} cells", state="complete")
            df = pd.DataFrame(summaries)
            if not df.empty:
                st.success(f"Run `{df['run_id'].iloc[0]}` saved — open it in the Results explorer.",
                           icon=":material/check_circle:")
                st.dataframe(df[[c for c in ["config", "concurrency", "repetition", "requests", "throughput_rps",
                                             "n_errors", "cpu_percent_mean"] if c in df]],
                             hide_index=True, width="stretch")
            st.page_link("views/results_explorer.py", label="Open results explorer", icon=":material/monitoring:")

with t_stream:
    llama_path = os.environ.get("PQ_SHIELD_LLAMA_MODEL_PATH", "")
    try:
        import llama_cpp  # noqa: F401
        llama_ok = os.path.isfile(llama_path)
    except ImportError:
        llama_ok = False
    backend = st.segmented_control("Token generator", ["Llama-3.2-3B (real)", "Synthetic (fast)"],
                                   default="Llama-3.2-3B (real)" if llama_ok else "Synthetic (fast)") or "Synthetic (fast)"
    if backend.startswith("Llama") and not llama_ok:
        st.warning("llama-cpp-python or the model file is unavailable; using the synthetic generator.")
        backend = "Synthetic (fast)"
    tps = None
    if backend.startswith("Synthetic"):
        tps = st.slider("Synthetic tokens per second", 10, 1000, 300)
    with st.form("stream"):
        c1, c2 = st.columns(2)
        with c1:
            sconfigs = st.multiselect("Configurations", PROT, default=["hybrid", "full-pqc"], format_func=lab)
            strategies = st.pills("Strategies", ["buffer_and_sign", "per_chunk", "hash_chain"], selection_mode="multi",
                                  default=["per_chunk", "hash_chain"],
                                  format_func={"buffer_and_sign": "Buffer & sign", "per_chunk": "Per-chunk",
                                               "hash_chain": "Hash chain"}.get)
            ks = st.pills("Hash-chain checkpoint intervals", ["none", 1, 2, 5, 10, 20], selection_mode="multi",
                          default=["none"], help="Each value adds a hash-chain variant signing every k chunks.")
        with c2:
            lengths = st.pills("Response lengths (tokens)", [20, 50, 100, 200, 500], selection_mode="multi", default=[50])
            chunks = st.pills("Tokens per chunk", [1, 5, 10, 20], selection_mode="multi", default=[5])
            sreps = st.number_input("Repetitions", 1, 10, 2)
        go2 = st.form_submit_button("Run streaming sweep", type="primary", icon=":material/play_arrow:")
    if go2:
        if not (sconfigs and strategies and lengths and chunks):
            st.error("Pick at least one of each.")
        else:
            os.environ["PQ_SHIELD_STREAMING_BACKEND"] = "llama_cpp" if backend.startswith("Llama") else "synthetic"
            if tps:
                os.environ["PQ_SHIELD_SYNTHETIC_TOKENS_PER_SEC"] = str(tps)
            from bench.streaming_runner import run_sweep

            k_values = [None if k == "none" else int(k) for k in (ks or ["none"])]
            with st.status("Streaming sweep running…") as status:
                rows = run_sweep(configs=sconfigs, strategies=strategies, max_tokens_values=sorted(lengths),
                                 chunk_size_values=sorted(chunks), repetitions=int(sreps), port=8000,
                                 output_dir=os.path.join(REPO_ROOT, "results", "streaming"),
                                 log_dir=os.path.join(REPO_ROOT, "results", "server_logs"),
                                 checkpoint_intervals=k_values if "hash_chain" in strategies else None)
                n_err = sum(1 for r in rows if r.get("error"))
                status.update(label=f"Done — {len(rows)} streams, {n_err} errors",
                              state="complete" if not n_err else "error")
            st.dataframe(pd.DataFrame(rows)[[c for c in ["config", "strategy", "checkpoint_interval", "max_tokens",
                                                          "ttft_ms", "total_signature_bytes", "n_signatures",
                                                          "stream_fully_verified", "error"]
                                             if c in rows[0]]], hide_index=True, width="stretch")
            st.page_link("views/results_explorer.py", label="Open results explorer", icon=":material/monitoring:")
