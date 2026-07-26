"""Train the lightweight, deterministic inference workload used by PQ-Shield."""

from pathlib import Path

import joblib
from sklearn.datasets import load_digits
from sklearn.ensemble import RandomForestClassifier

ARTIFACT = Path(__file__).parent / "artifacts" / "model.pkl"


def train() -> Path:
    """Train and persist the 64-feature digit model used by both API paths."""
    dataset = load_digits()
    model = RandomForestClassifier(
        n_estimators=100, random_state=20768, n_jobs=-1
    )
    model.fit(dataset.data, dataset.target)
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, ARTIFACT)
    return ARTIFACT


if __name__ == "__main__":
    print(f"Saved model to {train()}")
