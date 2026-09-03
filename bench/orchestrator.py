"""Orchestrates the full benchmark matrix: for each configuration, starts
the matching uvicorn server fresh, runs bench.runner.run_sweep_cell for
every (concurrency, repetition) pair, then kills the server before moving
to the next configuration -- so no two configurations ever share a process
or contend for the same CPU core at the same time.

Usage:
    python -m bench.orchestrator --configs control,classical,hybrid,full-pqc \
        --concurrency 10,100,1000 --repetitions 5 --requests-per-concurrency 10

`--requests-per-concurrency` sets requests = concurrency * this value for
each cell (matching the design doc's `concurrency * 10` convention), with
`--min-requests` as a floor for low-concurrency cells.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import subprocess
import sys
import time

import httpx

from bench.runner import new_run_id, run_sweep_cell, write_csv
from crypto.instrumentation import ResourceSampler

SERVER_MODULES = {
    "control": "api.server:app",
    "classical": "api.server_config_a:app",
    "hybrid": "api.server_config_b:app",
    "full-pqc": "api.server_config_c:app",
}

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON_BIN = os.path.join(REPO_ROOT, ".venv", "bin", "python")
if not os.path.isfile(PYTHON_BIN):
    PYTHON_BIN = sys.executable


def _start_server(config_key: str, port: int, log_path: str, extra_env: dict | None = None) -> subprocess.Popen:
    module = SERVER_MODULES[config_key]
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    log_f = open(log_path, "w")
    proc = subprocess.Popen(
        [PYTHON_BIN, "-m", "uvicorn", module, "--port", str(port), "--log-level", "warning"],
        env=env,
        stdout=log_f,
        stderr=subprocess.STDOUT,
        cwd=REPO_ROOT,
        start_new_session=True,  # own process group, so we can kill children too
    )
    return proc


def _wait_healthy(base_url: str, timeout_s: float = 20.0) -> None:
    deadline = time.time() + timeout_s
    last_err = None
    while time.time() < deadline:
        try:
            resp = httpx.get(f"{base_url}/healthz", timeout=2.0)
            if resp.status_code == 200:
                return
        except Exception as exc:
            last_err = exc
        time.sleep(0.3)
    raise RuntimeError(f"Server at {base_url} did not become healthy: {last_err}")


def _stop_server(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)


def run_full_sweep(
    configs: list[str],
    concurrency_levels: list[int],
    repetitions: int,
    requests_per_concurrency: int,
    min_requests: int,
    port: int,
    raw_dir: str,
    log_dir: str,
    summary_dir: str | None = None,
    payload_profile: str = "tabular_small",
) -> list[dict]:
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)
    summary_dir = summary_dir or os.path.join(REPO_ROOT, "results", "sweep_summaries")
    os.makedirs(summary_dir, exist_ok=True)
    base_url = f"http://127.0.0.1:{port}"
    all_cell_summaries = []
    run_id = new_run_id()
    print(f"run_id={run_id}", flush=True)

    extra_env = {"PQ_SHIELD_PAYLOAD_PROFILE": payload_profile}
    # Also set it in *this* process's environment: run_sweep_cell's client-side
    # request generation (model.profiles.registry.get_profile()) runs in-process
    # here, not in the server subprocess, so both must agree on the profile.
    os.environ["PQ_SHIELD_PAYLOAD_PROFILE"] = payload_profile

    for config_key in configs:
        log_path = os.path.join(log_dir, f"server-{config_key}.log")
        print(f"\n=== Starting server: {config_key} ({SERVER_MODULES[config_key]}), "
              f"payload_profile={payload_profile} ===", flush=True)
        proc = _start_server(config_key, port, log_path, extra_env=extra_env)
        try:
            _wait_healthy(base_url)
            print(f"Server healthy (pid={proc.pid}).", flush=True)

            for concurrency in concurrency_levels:
                n_requests = max(min_requests, concurrency * requests_per_concurrency)
                for repetition in range(1, repetitions + 1):
                    fname = f"{config_key}-c{concurrency}-r{repetition}.csv"
                    out_path = os.path.join(raw_dir, fname)
                    print(
                        f"  -> {config_key} | concurrency={concurrency} | rep={repetition} "
                        f"| requests={n_requests}",
                        flush=True,
                    )
                    sampler = ResourceSampler(pid=proc.pid, interval_s=0.25)
                    sampler.start()
                    t0 = time.perf_counter()
                    rows = asyncio.run(
                        run_sweep_cell(
                            base_url, _crypto_name(config_key), concurrency, n_requests, repetition,
                            run_id=run_id,
                        )
                    )
                    wall_s = time.perf_counter() - t0
                    resource_summary = sampler.summary()  # server-process CPU%/RSS during this cell
                    write_csv(rows, out_path)
                    n_errors = sum(1 for r in rows if r["error"])
                    summary = {
                        "run_id": run_id,
                        "config": config_key,
                        "concurrency": concurrency,
                        "repetition": repetition,
                        "requests": n_requests,
                        "wall_seconds": wall_s,
                        "throughput_rps": len(rows) / wall_s if wall_s > 0 else None,
                        "n_errors": n_errors,
                        "output": out_path,
                        **resource_summary,
                    }
                    all_cell_summaries.append(summary)
                    cpu_mean = resource_summary.get("cpu_percent_mean")
                    cpu_str = f"{cpu_mean:.0f}% CPU" if cpu_mean is not None else "no CPU samples (cell too short)"
                    print(
                        f"     done in {wall_s:.2f}s, {summary['throughput_rps']:.1f} req/s, "
                        f"{n_errors} errors, server {cpu_str} -> {out_path}",
                        flush=True,
                    )
        finally:
            print(f"Stopping server: {config_key}", flush=True)
            _stop_server(proc)
            time.sleep(1.0)

    if all_cell_summaries:
        summary_path = os.path.join(summary_dir, f"{run_id}.json")
        with open(summary_path, "w") as f:
            json.dump(all_cell_summaries, f, indent=2)
        print(f"\nWrote per-cell summary (incl. resource usage) to {summary_path}", flush=True)

    return all_cell_summaries


def _crypto_name(config_key: str) -> str:
    return {"control": "control", "classical": "classical", "hybrid": "hybrid", "full-pqc": "full_pqc"}[
        config_key
    ]


def main():
    parser = argparse.ArgumentParser(description="PQ-Shield full benchmark matrix orchestrator")
    parser.add_argument("--configs", default="control,classical,hybrid,full-pqc")
    parser.add_argument("--concurrency", default="10,100,1000")
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--requests-per-concurrency", type=int, default=10)
    parser.add_argument("--min-requests", type=int, default=50)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--raw-dir", default=os.path.join(REPO_ROOT, "results", "raw"))
    parser.add_argument("--log-dir", default=os.path.join(REPO_ROOT, "results", "server_logs"))
    parser.add_argument("--summary-out", default=os.path.join(REPO_ROOT, "results", "sweep_summary.json"))
    parser.add_argument(
        "--payload-profile", default="tabular_small",
        choices=["tabular_small", "image_cnn", "embedding", "llm_completion"],
    )
    args = parser.parse_args()

    configs = [c.strip() for c in args.configs.split(",") if c.strip()]
    concurrency_levels = [int(c.strip()) for c in args.concurrency.split(",") if c.strip()]

    summaries = run_full_sweep(
        configs=configs,
        concurrency_levels=concurrency_levels,
        repetitions=args.repetitions,
        requests_per_concurrency=args.requests_per_concurrency,
        min_requests=args.min_requests,
        port=args.port,
        raw_dir=args.raw_dir,
        log_dir=args.log_dir,
        payload_profile=args.payload_profile,
    )

    os.makedirs(os.path.dirname(args.summary_out), exist_ok=True)
    with open(args.summary_out, "w") as f:
        json.dump(summaries, f, indent=2)
    print(f"\nWrote sweep summary to {args.summary_out}")


if __name__ == "__main__":
    main()
