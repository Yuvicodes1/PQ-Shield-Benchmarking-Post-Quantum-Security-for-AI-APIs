"""Create a concise comparison chart from PQ-Shield raw benchmark CSV files."""

import argparse
import csv
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev

import matplotlib.pyplot as plt


METRICS = (
    ("rtt_ms", "Protected request RTT (ms)"),
    ("handshake_ms", "Handshake time (ms)"),
    ("server_crypto_ms", "Server crypto + inference (ms)"),
)
CONFIGURATION_ORDER = ("control", "classical", "hybrid", "full-pqc")
CONFIGURATION_LABELS = {
    "control": "Control", "classical": "Classical", "hybrid": "Hybrid", "full-pqc": "Full PQC",
}


def load_records(paths: list[Path]) -> dict[str, list[dict[str, float]]]:
    records: dict[str, list[dict[str, float]]] = defaultdict(list)
    for path in paths:
        with path.open(newline="", encoding="utf-8") as stream:
            for row in csv.DictReader(stream):
                if row["ok"].lower() == "true":
                    records[row["configuration"]].append({
                        metric: float(row[metric]) for metric, _ in METRICS
                    })
    return records


def plot(records: dict[str, list[dict[str, float]]], output: Path) -> None:
    configurations = [name for name in CONFIGURATION_ORDER if records.get(name)]
    if not configurations:
        raise ValueError("No successful benchmark records were found")

    figure, axes = plt.subplots(1, len(METRICS), figsize=(15, 4.8), constrained_layout=True)
    colors = ["#4C78A8", "#F58518", "#54A24B", "#B279A2"]
    for axis, (metric, title) in zip(axes, METRICS):
        values = [mean(record[metric] for record in records[name]) for name in configurations]
        errors = [
            stdev(record[metric] for record in records[name]) if len(records[name]) > 1 else 0
            for name in configurations
        ]
        bars = axis.bar(
            [CONFIGURATION_LABELS[name] for name in configurations], values,
            yerr=errors, capsize=4, color=colors[:len(configurations)], edgecolor="#333333",
        )
        axis.set_title(title)
        axis.set_ylabel("Milliseconds")
        axis.grid(axis="y", alpha=0.25)
        axis.set_axisbelow(True)
        for bar, value in zip(bars, values):
            axis.text(bar.get_x() + bar.get_width() / 2, value, f"{value:.1f}",
                      ha="center", va="bottom", fontsize=9)

    sample_count = sum(len(records[name]) for name in configurations)
    figure.suptitle(f"PQ-Shield benchmark comparison ({sample_count} successful requests)", fontsize=14)
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, dpi=180, bbox_inches="tight")


def main() -> None:
    parser = argparse.ArgumentParser(description="Plot aggregate PQ-Shield benchmark metrics.")
    parser.add_argument("--input", type=Path, nargs="+", default=sorted(Path("results/raw").glob("*.csv")))
    parser.add_argument("--output", type=Path, default=Path("outputs/benchmark-comparison.png"))
    args = parser.parse_args()
    plot(load_records(args.input), args.output)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
