"""Runs every experiment the journal paper reports, in one sequential pass on
one host, and records each sweep's run_id in results/paper_runs.json so
`python -m analysis.paper_figures` picks them up with no flags.

Order (each step is independent; a failing step is logged and skipped, and
the manifest is rewritten after every step so a partial run is still usable):

  1. primitive micro-benchmark            validation.primitive_bench
  2. concurrency matrix                   5 configs x {10,100,1000} x 5 reps
  3. payload-shape sweep                  4 profiles x 5 configs x c=10 x 5 reps
  4. network-emulation sweep              4 paths x 5 configs x c=10 x 5 reps
  5. single-transaction HNDL + MITM       4 protected configs
  6. streaming strategies (real Llama)    4 configs x 3 strategies x {50,200} tok x 10 reps
  7. streaming HNDL (real Llama)          4 configs x {50,200,500,2000} tok
  8. streaming sequence attacks (Llama)   4 configs x 3 strategies x {drop,reorder} x 10 trials
  9. checkpoint frontier (Llama)          hash-chain, k in {1,2,5,10,20,inf}, Hybrid + Full PQC x 5 reps
 10. checkpoint sequence attacks (Llama)  same k values, drop/reorder x 5 trials
 11. handshake amortization              6 configs x {1,10,100} requests per key exchange x 5 reps
 12. concurrency supplement              Control (re-run after endpoint fix) + Hybrid-KEX, same settings as step 2

Nothing else should run on the machine meanwhile -- every step measures time.
Existing threat/validation result files are copied to
results/archive/pre_rerun_<timestamp>/ before being overwritten.

Usage:
    python -m bench.paper_runs                 # everything (~3 h)
    python -m bench.paper_runs --steps 6,7,8   # a subset
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import traceback

from bench.orchestrator import PYTHON_BIN, REPO_ROOT, _start_server, _stop_server, _wait_healthy, run_full_sweep

RESULTS = os.path.join(REPO_ROOT, "results")
MANIFEST = os.path.join(RESULTS, "paper_runs.json")
ALL_CONFIGS = ["control", "classical", "classical-ecdhe", "hybrid", "hybrid-kex", "full-pqc"]
PROTECTED = ["classical", "classical-ecdhe", "hybrid", "hybrid-kex", "full-pqc"]
CRYPTO = {"classical": "classical", "classical-ecdhe": "classical_ecdhe", "hybrid": "hybrid",
          "hybrid-kex": "hybrid_kex", "full-pqc": "full_pqc"}
CHECKPOINT_KS = [None, 1, 2, 5, 10, 20]
PROFILES = ["tabular_small", "image_cnn", "embedding", "llm_completion"]
NETWORKS = ["localhost", "metro", "wan", "mobile"]
PORT = 8000


def _log(msg: str) -> None:
    print(f"\n[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _load_manifest() -> dict:
    if os.path.isfile(MANIFEST):
        with open(MANIFEST) as f:
            return json.load(f)
    return {}


def _save_manifest(m: dict) -> None:
    with open(MANIFEST, "w") as f:
        json.dump(m, f, indent=2)


def _run(cmd: list[str], env: dict | None = None) -> None:
    full_env = {**os.environ, **(env or {})}
    subprocess.run(cmd, cwd=REPO_ROOT, env=full_env, check=True)


def _archive() -> str:
    dest = os.path.join(RESULTS, "archive", f"pre_rerun_{time.strftime('%Y%m%dT%H%M%S')}")
    for sub in ["hndl", "mitm", os.path.join("streaming", "mitm"), "validation"]:
        src = os.path.join(RESULTS, sub)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(dest, sub), dirs_exist_ok=True)
    return dest


def _sweep(**kw) -> str:
    cells = run_full_sweep(port=PORT, raw_dir=os.path.join(RESULTS, "raw"),
                           log_dir=os.path.join(RESULTS, "server_logs"), **kw)
    return cells[0]["run_id"]


# --------------------------------------------------------------------------- steps

def step_primitives(m: dict) -> None:
    _run([PYTHON_BIN, "-m", "validation.primitive_bench", "--iterations", "2000",
          "--output", os.path.join(RESULTS, "validation", "primitive_bench.json")])
    m["primitives"] = "results/validation/primitive_bench.json"


def step_concurrency(m: dict) -> None:
    m["concurrency"] = _sweep(configs=ALL_CONFIGS, concurrency_levels=[10, 100, 1000], repetitions=5,
                              requests_per_concurrency=10, min_requests=50)


def step_payload(m: dict) -> None:
    m["payload"] = []
    for prof in PROFILES:
        m["payload"].append(_sweep(configs=ALL_CONFIGS, concurrency_levels=[10], repetitions=5,
                                   requests_per_concurrency=10, min_requests=100, payload_profile=prof))
        _save_manifest(m)


def step_network(m: dict) -> None:
    m["network"] = []
    for net in NETWORKS:
        m["network"].append(_sweep(configs=ALL_CONFIGS, concurrency_levels=[10], repetitions=5,
                                   requests_per_concurrency=10, min_requests=100, network_profile=net))
        _save_manifest(m)


def step_threats(m: dict, configs: list[str] | None = None) -> None:
    os.makedirs(os.path.join(RESULTS, "hndl"), exist_ok=True)
    os.makedirs(os.path.join(RESULTS, "mitm"), exist_ok=True)
    for cfg in configs or PROTECTED:
        crypto = CRYPTO[cfg]
        proc = _start_server(cfg, PORT, os.path.join(RESULTS, "server_logs", f"threat-server-{cfg}.log"))
        try:
            _wait_healthy(f"http://127.0.0.1:{PORT}")
            _log(f"HNDL capture: {cfg}")
            _run([PYTHON_BIN, "-m", "threats.hndl_capture", "--configuration", cfg,
                  "--url", f"http://127.0.0.1:{PORT}", "--requests", "1000",
                  "--output", os.path.join(RESULTS, "hndl", f"{crypto}-hndl.csv")])
            for target in ["ciphertext", "signature"]:
                _log(f"MITM {target} tampering: {cfg}")
                proxy = subprocess.Popen(
                    [PYTHON_BIN, "-m", "threats.mitm_harness", "--upstream", f"http://127.0.0.1:{PORT}",
                     "--listen-port", str(PORT + 1000), "--tamper-target", target],
                    cwd=REPO_ROOT, start_new_session=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    time.sleep(1.5)
                    _run([PYTHON_BIN, "-m", "threats.mitm_experiment", "--configuration", cfg,
                          "--proxy-url", f"http://127.0.0.1:{PORT + 1000}", "--requests", "100",
                          "--tamper-target", target,
                          "--output", os.path.join(RESULTS, "mitm", f"{crypto}-mitm-{target}.csv")])
                finally:
                    _stop_server(proxy)
                    time.sleep(0.5)
        finally:
            _stop_server(proc)
            time.sleep(1.0)
    m["threats"] = "results/hndl/*-hndl-summary.json, results/mitm/*-summary.json"


def _llama_env() -> dict:
    return {"PQ_SHIELD_STREAMING_BACKEND": "llama_cpp"}


def step_streaming(m: dict) -> None:
    os.environ.update(_llama_env())  # streaming_runner reads it per sweep; servers inherit it
    from bench.streaming_runner import run_sweep
    rows = run_sweep(configs=PROTECTED, strategies=["buffer_and_sign", "per_chunk", "hash_chain"],
                     max_tokens_values=[50, 200], chunk_size_values=[5], repetitions=10, port=PORT,
                     output_dir=os.path.join(RESULTS, "streaming"),
                     log_dir=os.path.join(RESULTS, "server_logs"),
                     warmup_transactions=1, shuffle_seed=1)
    m["streaming"] = rows[0]["run_id"]
    m["streaming_backend"] = "llama_cpp"


def step_streaming_hndl(m: dict) -> None:
    _run([PYTHON_BIN, "-m", "threats.streaming_hndl_experiment", "--configs", ",".join(PROTECTED),
          "--port", str(PORT), "--max-tokens", "50,200,500,2000"], env=_llama_env())
    m["streaming_hndl"] = "results/hndl/streaming/ (llama_cpp)"


def step_streaming_mitm(m: dict) -> None:
    _run([PYTHON_BIN, "-m", "threats.streaming_mitm_experiment", "--configs", ",".join(PROTECTED),
          "--port", str(PORT), "--trials", "10"], env=_llama_env())
    m["streaming_mitm"] = "results/streaming/mitm/ (llama_cpp)"


def step_checkpoint(m: dict) -> None:
    os.environ.update(_llama_env())
    from bench.streaming_runner import run_sweep
    rows = run_sweep(configs=["hybrid", "full-pqc"], strategies=["hash_chain"], max_tokens_values=[200],
                     chunk_size_values=[5], repetitions=5, port=PORT,
                     output_dir=os.path.join(RESULTS, "streaming"), log_dir=os.path.join(RESULTS, "server_logs"),
                     warmup_transactions=1, shuffle_seed=2, checkpoint_intervals=CHECKPOINT_KS)
    m["checkpoint"] = rows[0]["run_id"]


def step_checkpoint_attacks(m: dict) -> None:
    _run([PYTHON_BIN, "-m", "threats.streaming_mitm_experiment", "--configs", "hybrid,full-pqc",
          "--strategies", "hash_chain", "--attacks", "drop,reorder", "--trials", "5", "--max-tokens", "200",
          "--checkpoint-intervals", ",".join(str(k) for k in CHECKPOINT_KS if k), "--port", str(PORT)],
         env=_llama_env())
    m["checkpoint_attacks"] = "results/streaming/mitm/checkpoints/ (llama_cpp)"


def step_amortization(m: dict) -> None:
    m["amortization"] = []
    for n in [1, 10, 100]:
        # 1,000 requests over 10 workers = ~100 per worker, so a 100-request session completes.
        m["amortization"].append(_sweep(configs=ALL_CONFIGS, concurrency_levels=[10], repetitions=5,
                                        requests_per_concurrency=100, min_requests=1000,
                                        requests_per_handshake=n))
        _save_manifest(m)


def step_concurrency_supplement(m: dict) -> None:
    """Control (re-run after its endpoint was fixed to run in the thread pool,
    like the protected ones) and Hybrid-KEX (added after the main sweep),
    with the main sweep's exact settings. analysis.paper_figures keeps each
    config's latest run, so these supersede the main sweep's Control rows."""
    m["concurrency_supplement"] = _sweep(configs=["control", "hybrid-kex"], concurrency_levels=[10, 100, 1000],
                                         repetitions=5, requests_per_concurrency=10, min_requests=50)


STEPS = {
    1: ("primitive micro-benchmark", step_primitives),
    2: ("concurrency matrix", step_concurrency),
    3: ("payload-shape sweep", step_payload),
    4: ("network-emulation sweep", step_network),
    5: ("single-transaction HNDL + MITM", step_threats),
    6: ("streaming strategies (Llama)", step_streaming),
    7: ("streaming HNDL (Llama)", step_streaming_hndl),
    8: ("streaming sequence attacks (Llama)", step_streaming_mitm),
    9: ("checkpoint frontier (Llama)", step_checkpoint),
    10: ("checkpoint sequence attacks (Llama)", step_checkpoint_attacks),
    11: ("handshake amortization", step_amortization),
    12: ("concurrency supplement: Control re-run + Hybrid-KEX", step_concurrency_supplement),
}


def main() -> None:
    ap = argparse.ArgumentParser(description="Run every PQ-Shield experiment the paper reports")
    ap.add_argument("--steps", default=",".join(str(k) for k in STEPS), help="Comma-separated step numbers")
    ap.add_argument("--no-figures", action="store_true", help="Skip regenerating paper figures at the end")
    args = ap.parse_args()
    steps = [int(s) for s in args.steps.split(",") if s.strip()]

    # .env carries PQ_SHIELD_OQS_LIB and the Llama model path; servers inherit os.environ.
    from webapp.bootstrap import load_dotenv_if_needed
    load_dotenv_if_needed()
    os.environ.pop("ANTHROPIC_API_KEY", None)  # not needed by any experiment

    m = _load_manifest()
    m.setdefault("started", time.strftime("%Y-%m-%dT%H:%M:%S"))
    if any(s in steps for s in (1, 5, 7, 8, 10)):
        m["archive"] = _archive()
        _log(f"Archived existing threat/validation results to {m['archive']}")
    _save_manifest(m)

    failed = []
    for n in steps:
        name, fn = STEPS[n]
        _log(f"=== STEP {n}: {name} ===")
        t0 = time.time()
        try:
            fn(m)
            m.setdefault("completed_steps", [])
            if n not in m["completed_steps"]:
                m["completed_steps"].append(n)
            _log(f"STEP {n} done in {(time.time() - t0) / 60:.1f} min")
        except Exception:
            failed.append(n)
            traceback.print_exc()
            _log(f"STEP {n} FAILED after {(time.time() - t0) / 60:.1f} min -- continuing")
        m["failed_steps"] = failed
        _save_manifest(m)

    m["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    _save_manifest(m)
    _log(f"All done. Failed steps: {failed or 'none'}. Manifest: {MANIFEST}")
    if not args.no_figures:
        _run([PYTHON_BIN, "-m", "analysis.paper_figures"])
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
