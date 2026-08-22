"""Metric structures and CSV persistence for benchmark runs."""

from dataclasses import asdict, dataclass
from pathlib import Path
import csv


@dataclass(frozen=True)
class RequestMetric:
    configuration: str
    concurrency: int
    repetition: int
    request_index: int
    rtt_ms: float
    handshake_ms: float
    server_crypto_ms: float
    process_cpu_seconds: float
    process_rss_bytes: int
    ok: bool
    error: str = ""


def write_metrics(metrics: list[RequestMetric], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not metrics:
        return
    with destination.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(asdict(metrics[0])))
        writer.writeheader()
        writer.writerows(asdict(metric) for metric in metrics)
