"""Trains and serializes the primary inference workload: a 100-tree
RandomForestClassifier on the UCI Optical Recognition of Handwritten Digits
dataset (via sklearn.datasets.load_digits), matching the Review 1 proposal.

Model accuracy is explicitly not the point of this project -- the model is
a stand-in for "a real-time AI inference workload" so that PQ-Shield
measures PQC overhead against genuine request/response JSON payloads
(0.5 KB request / 0.2 KB response) rather than synthetic byte blobs.

Run: python -m model.train
"""

from __future__ import annotations

import json
import os
import time

import joblib
import numpy as np
from sklearn.datasets import load_digits
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

ARTIFACT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "artifacts")
MODEL_PATH = os.path.join(ARTIFACT_DIR, "model.pkl")
METADATA_PATH = os.path.join(ARTIFACT_DIR, "model_metadata.json")


def train() -> dict:
    os.makedirs(ARTIFACT_DIR, exist_ok=True)

    X, y = load_digits(return_X_y=True)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    t0 = time.perf_counter()
    clf.fit(X_train, y_train)
    train_ms = (time.perf_counter() - t0) * 1000

    test_accuracy = clf.score(X_test, y_test)

    # Representative single-sample payload sizes, for the paper's Table on
    # dataset/payload specifications.
    sample = X_test[0].reshape(1, -1)
    request_json = json.dumps({"input": sample.flatten().tolist()})
    proba = clf.predict_proba(sample)[0].tolist()
    pred = int(clf.predict(sample)[0])
    response_json = json.dumps({"prediction": pred, "probabilities": proba})

    joblib.dump(clf, MODEL_PATH)

    metadata = {
        "model": "RandomForestClassifier",
        "n_estimators": 100,
        "dataset": "UCI Optical Recognition of Handwritten Digits (sklearn.datasets.load_digits)",
        "n_samples": int(X.shape[0]),
        "n_features": int(X.shape[1]),
        "n_classes": int(len(np.unique(y))),
        "test_accuracy": test_accuracy,
        "train_ms": train_ms,
        "request_payload_bytes_approx": len(request_json.encode()),
        "response_payload_bytes_approx": len(response_json.encode()),
    }
    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)

    return metadata


if __name__ == "__main__":
    meta = train()
    print(json.dumps(meta, indent=2))
