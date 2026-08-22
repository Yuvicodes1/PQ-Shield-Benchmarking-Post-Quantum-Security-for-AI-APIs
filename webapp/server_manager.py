"""Manages the four demo servers (control, classical, hybrid, full_pqc) that
the Streamlit "Live Demo" and "Threat Scenarios" pages talk to over real
HTTP -- reused directly from bench/orchestrator.py's subprocess helpers so
the demo goes through exactly the same server code path as the paper's
benchmark, just on dedicated ports (8100-8103) so it never collides with a
concurrent bench.orchestrator run on the default port 8000.

Server processes are tracked by PID in st.session_state so they survive
Streamlit reruns (every widget interaction reruns the script from top to
bottom) without being re-launched each time; `ensure_server` is a cheap
health-check + no-op if already running.
"""

from __future__ import annotations

import os

import httpx
import psutil
import streamlit as st

from bench.orchestrator import REPO_ROOT, SERVER_MODULES, _start_server, _wait_healthy

DEMO_PORTS = {"control": 8100, "classical": 8101, "hybrid": 8102, "full_pqc": 8103}

# webapp/demo code uses crypto-module names ("full_pqc"); bench.orchestrator
# uses hyphenated config keys ("full-pqc") for its SERVER_MODULES lookup.
CONFIG_KEY = {"control": "control", "classical": "classical", "hybrid": "hybrid", "full_pqc": "full-pqc"}

DISPLAY_NAME = {
    "control": "Control (unprotected)",
    "classical": "A — Classical (RSA-2048 + ECDSA)",
    "hybrid": "B — Hybrid (ML-KEM-768 + ECDSA)",
    "full_pqc": "C — Full PQC (ML-KEM-768 + ML-DSA-65)",
}


def get_base_url(crypto_name: str) -> str:
    return f"http://127.0.0.1:{DEMO_PORTS[crypto_name]}"


def is_healthy(base_url: str, timeout_s: float = 1.5) -> bool:
    try:
        resp = httpx.get(f"{base_url}/healthz", timeout=timeout_s)
        return resp.status_code == 200
    except Exception:
        return False


def ensure_server(crypto_name: str) -> str:
    """Starts the demo server for this configuration if it isn't already
    responding to /healthz. Returns the base URL either way."""
    base_url = get_base_url(crypto_name)
    if is_healthy(base_url):
        return base_url

    if "demo_server_pids" not in st.session_state:
        st.session_state.demo_server_pids = {}

    config_key = CONFIG_KEY[crypto_name]
    port = DEMO_PORTS[crypto_name]
    log_dir = os.path.join(REPO_ROOT, "results", "server_logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"webapp-{crypto_name}.log")

    proc = _start_server(config_key, port, log_path)
    _wait_healthy(base_url, timeout_s=25.0)
    st.session_state.demo_server_pids[crypto_name] = proc.pid
    return base_url


def stop_server(crypto_name: str) -> None:
    """Terminates the demo server process for this configuration, if running."""
    port = DEMO_PORTS[crypto_name]
    for proc in psutil.process_iter(["pid", "cmdline"]):
        cmdline = proc.info.get("cmdline") or []
        joined = " ".join(cmdline)
        if "uvicorn" in joined and SERVER_MODULES[CONFIG_KEY[crypto_name]] in joined and str(port) in cmdline:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
    st.session_state.get("demo_server_pids", {}).pop(crypto_name, None)


def stop_all_servers() -> None:
    for crypto_name in DEMO_PORTS:
        stop_server(crypto_name)


def server_status() -> dict[str, dict]:
    """Returns {crypto_name: {"running": bool, "base_url": str, "port": int}} for the status panel."""
    return {
        name: {
            "running": is_healthy(get_base_url(name)),
            "base_url": get_base_url(name),
            "port": DEMO_PORTS[name],
        }
        for name in DEMO_PORTS
    }
