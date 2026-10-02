"""Does in-process Llama generation inflate wall-clock signing times?

The streaming harness signs on the server's event-loop thread while
llama-cpp-python generates tokens in a worker thread of the same process.
Wall-clock timers around sign() then include time spent waiting for the GIL
or the CPU, not only the signature itself. This script measures the effect
directly: it signs N messages with each scheme (a) idle and (b) while Llama
generates in a background thread, recording both wall-clock and thread-CPU
time per call.

    python -m validation.contention_check --n 300 --out results/validation/contention_check.csv
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import os
import statistics
import threading
import time
from pathlib import Path

from crypto.registry import get_client_crypto, get_server_crypto

SCHEMES = {"ECDSA-P256": "hybrid", "ML-DSA-65": "full_pqc"}
MESSAGE = b"x" * 64


def _busy_wait(seconds: float) -> None:
    t = time.perf_counter()
    while time.perf_counter() - t < seconds:
        pass


def _set_qos(qos_class: int) -> None:
    """macOS thread QoS; QOS_CLASS_BACKGROUND (0x09) confines the thread to
    the efficiency cores. No-op elsewhere."""
    try:
        ctypes.CDLL("/usr/lib/libSystem.dylib").pthread_set_qos_class_self_np(qos_class, 0)
    except OSError:
        pass


def _measure(config: str, n: int, phase: str, gap_s: float = 0.0, busy: bool = False) -> list[dict]:
    server = get_server_crypto(config)
    client = get_client_crypto(config)
    bundle = server.new_handshake()
    rows = []
    for i in range(n + 20):
        if gap_s and i >= 20:
            # one signature per chunk, as in a token stream; busy=True keeps the core loaded
            _busy_wait(gap_s) if busy else time.sleep(gap_s)
        sig, smeta = server.sign(bundle.handshake_id, MESSAGE)
        ok, vmeta = client.verify(MESSAGE, sig, bundle.sig_public_key)
        assert ok
        if i < 20:  # discard lazy-initialization warm-up calls
            continue
        rows.append({"phase": phase, "config": config, "i": i - 20,
                     "sign_wall_ms": smeta["sign_ms"], "sign_cpu_ms": smeta["sign_cpu_ms"],
                     "verify_wall_ms": vmeta["verify_ms"], "verify_cpu_ms": vmeta["verify_cpu_ms"]})
    server.forget(bundle.handshake_id)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--gap-ms", type=float, default=125.0,
                    help="spacing for the 'spaced' phases (one 5-token chunk at ~40 tok/s)")
    ap.add_argument("--n-spaced", type=int, default=100)
    ap.add_argument("--out", default="results/validation/contention_check.csv")
    args = ap.parse_args()

    from model.streaming_backends.llama_cpp_backend import LlamaCppStreamingBackend
    os.environ.setdefault("PQ_SHIELD_LLAMA_MODEL_PATH", "models/Llama-3.2-3B-Instruct-Q4_K_M.gguf")
    backend = LlamaCppStreamingBackend()
    for _ in backend.stream("Warm up.", 8):
        pass

    rows: list[dict] = []
    gap = args.gap_ms / 1000
    for scheme, cfg in SCHEMES.items():
        rows += _measure(cfg, args.n, "idle")
        rows += _measure(cfg, args.n_spaced, "idle_spaced", gap)
        # same spacing, core kept busy: separates "idle gap" from "spacing" itself
        rows += _measure(cfg, args.n_spaced, "busy_spaced", gap, busy=True)

    stop = threading.Event()

    def _generate():
        while not stop.is_set():
            for _ in backend.stream("Explain post-quantum cryptography in detail.", 400):
                if stop.is_set():
                    break

    # efficiency cores only (macOS QoS background), back to back, in a separate thread
    def _ecores():
        _set_qos(0x09)
        for scheme, cfg in SCHEMES.items():
            rows.extend(_measure(cfg, args.n, "ecores"))

    t_e = threading.Thread(target=_ecores)
    t_e.start()
    t_e.join()

    gen = threading.Thread(target=_generate, daemon=True)
    gen.start()
    try:
        for scheme, cfg in SCHEMES.items():
            rows += _measure(cfg, args.n, "llama_generating")
            rows += _measure(cfg, args.n_spaced, "llama_spaced", gap)
    finally:
        stop.set()
        gen.join(timeout=30)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print(f"{'scheme':<11}{'phase':<18}{'sign wall':>10}{'sign cpu':>10}{'mean wall':>10}{'ver wall':>10}{'ver cpu':>10}  (us; median unless noted)")
    for scheme, cfg in SCHEMES.items():
        for phase in ("idle", "idle_spaced", "busy_spaced", "ecores", "llama_generating", "llama_spaced"):
            sel = [r for r in rows if r["config"] == cfg and r["phase"] == phase]
            med = lambda k: statistics.median(r[k] for r in sel) * 1000
            p90 = statistics.mean(r["sign_wall_ms"] for r in sel) * 1000
            print(f"{scheme:<11}{phase:<18}{med('sign_wall_ms'):>10.1f}{med('sign_cpu_ms'):>10.1f}{p90:>10.1f}"
                  f"{med('verify_wall_ms'):>10.1f}{med('verify_cpu_ms'):>10.1f}")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
