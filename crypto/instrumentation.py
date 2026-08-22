"""Timing and resource-usage instrumentation shared across crypto configs.

Two things live here:
  - `Timer`: a tiny context manager that records wall-clock milliseconds,
    used inline by every crypto operation (keygen, handshake, sign, verify)
    so per-operation costs can be attributed rather than only measuring
    end-to-end RTT.
  - `ResourceSampler`: a background-thread psutil sampler for CPU% and RSS,
    used by bench/runner.py during load-generation windows (Phase 5 of the
    design doc's statistical-rigor checklist).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

import psutil


class Timer:
    """Context manager measuring wall-clock elapsed time in milliseconds.

    Usage:
        with Timer() as t:
            do_something()
        t.elapsed_ms
    """

    def __enter__(self) -> "Timer":
        self._t0 = time.perf_counter()
        self.elapsed_ms = 0.0
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.elapsed_ms = (time.perf_counter() - self._t0) * 1000.0


@dataclass
class ResourceSample:
    timestamp: float
    cpu_percent: float
    rss_mb: float


@dataclass
class ResourceSampler:
    """Samples CPU% and RSS of a given PID on a fixed interval in a background thread.

    CPU% here is *process*-relative (psutil's `cpu_percent`), not
    system-wide, since the design goal is attributing overhead to the
    server process running a given crypto configuration, not whatever else
    is running on the host.
    """

    pid: int
    interval_s: float = 0.5
    samples: list = field(default_factory=list)
    _stop_event: threading.Event = field(default_factory=threading.Event, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)

    def start(self) -> None:
        try:
            proc = psutil.Process(self.pid)
            proc.cpu_percent(interval=None)  # prime the internal counter
        except psutil.NoSuchProcess:
            return

        def _run():
            proc = psutil.Process(self.pid)
            while not self._stop_event.is_set():
                try:
                    cpu = proc.cpu_percent(interval=None)
                    rss = proc.memory_info().rss / (1024 * 1024)
                    self.samples.append(ResourceSample(time.time(), cpu, rss))
                except psutil.NoSuchProcess:
                    break
                self._stop_event.wait(self.interval_s)

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()

    def stop(self) -> list:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        return self.samples

    def summary(self) -> dict:
        if not self.samples:
            return {"cpu_percent_mean": None, "rss_mb_mean": None, "rss_mb_max": None}
        cpu_vals = [s.cpu_percent for s in self.samples]
        rss_vals = [s.rss_mb for s in self.samples]
        return {
            "cpu_percent_mean": sum(cpu_vals) / len(cpu_vals),
            "cpu_percent_max": max(cpu_vals),
            "rss_mb_mean": sum(rss_vals) / len(rss_vals),
            "rss_mb_max": max(rss_vals),
            "n_samples": len(self.samples),
        }
