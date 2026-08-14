# PQ-Shield

PQ-Shield is an empirical framework for measuring the security and performance trade-offs of post-quantum cryptography (PQC) around a latency-sensitive AI inference API.

The project compares the same FastAPI digit-classifier workload in three protected configurations:

| Configuration | Key establishment | Response signature | Purpose |
| --- | --- | --- | --- |
| Control | None | None | Unprotected performance reference. |
| A - Classical | RSA-2048/OAEP | ECDSA P-256 | Current classical baseline. |
| B - Hybrid | ML-KEM-768 | ECDSA P-256 | Incremental PQC migration path. |
| C - Full PQC | ML-KEM-768 | ML-DSA-65 | Quantum-resistant key establishment and signatures. |

The inference workload is a deterministic 100-tree scikit-learn Random Forest trained on the 64-feature UCI handwritten-digits dataset. Each request returns a predicted digit and its ten class probabilities. The cryptographic wrappers do not change model behavior; they protect the JSON request and response around it.

## Current progress

Implemented and verified:

- Control FastAPI endpoint: `POST /predict`.
- Configuration A: RSA-OAEP key transport, AES-256-GCM payload encryption, and ECDSA P-256 response signatures.
- Configuration B: ML-KEM-768 key establishment, AES-256-GCM payload encryption, and ECDSA P-256 response signatures.
- Configuration C: ML-KEM-768 key establishment, AES-256-GCM payload encryption, and ML-DSA-65 response signatures.
- Local `liboqs` integration through small `ctypes` adapters; no system-wide installation is required.
- Async benchmark runner for control, classical, hybrid, and full-PQC runs.
- Raw CSV metrics and an aggregate latency/handshake/server-time plot.
- End-to-end protocol tests, including ML-DSA tamper detection.

Current gaps before the final project goal:

- Run the complete benchmark matrix: A/B/C × concurrency 10/100/1000 × five repetitions.
- Add the HNDL capture/storage experiment and active MITM tamper-detection harness.
- Add percentile aggregation, CPU/memory analysis, and the weighted security-performance decision matrix.
- Add the planned larger-payload/CIFAR-10 sensitivity workload and Dockerized reproducibility.

## Prerequisites

- Python 3.11 is recommended (the local implementation is compatible with Python 3.9+).
- CMake, a C compiler, and Git, for the local `liboqs` build.
- macOS: Xcode Command Line Tools provide the compiler. Linux: install `build-essential cmake git`.

## Setup

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m model.train
bash scripts/install_oqs.sh
```

`install_oqs.sh` builds ML-KEM-768 and ML-DSA-65 under `work/oqs-prefix/`. To use another local liboqs build, set `PQ_SHIELD_OQS_LIB` to its absolute dynamic-library path.

Run the test suite after setup:

```bash
python -m pytest -q
```

Use `python -m pytest`, rather than the bare `pytest` executable, so Python resolves this repository's `api` and `crypto` packages correctly.

## Run the API and make a prediction

Use one server at a time. The protected configurations expose two routes:

- `GET /secure/handshake` returns public key material.
- `POST /secure/predict` accepts the protected request and returns an encrypted, signed prediction.

### Control server

```bash
source .venv/bin/activate
uvicorn api.server:app --port 8000
```

In a second terminal, test the plain endpoint:

```bash
curl -X POST http://127.0.0.1:8000/predict \
  -H 'Content-Type: application/json' \
  -d '{"input":[0,0,5,13,9,1,0,0,0,0,13,15,10,15,5,0,0,3,15,2,0,11,8,0,0,4,12,0,0,8,8,0,0,5,8,0,0,9,8,0,0,4,11,0,1,12,7,0,0,2,14,5,10,12,0,0,0,0,6,13,10,0,0,0]}'
```

### Configuration A - Classical

Terminal 1:

```bash
source .venv/bin/activate
uvicorn api.server_config_a:app --port 8000
```

Terminal 2:

```bash
source .venv/bin/activate
python -m api.client --url http://127.0.0.1:8000 --features 0,0,5,13,9,1,0,0,0,0,13,15,10,15,5,0,0,3,15,2,0,11,8,0,0,4,12,0,0,8,8,0,0,5,8,0,0,9,8,0,0,4,11,0,1,12,7,0,0,2,14,5,10,12,0,0,0,0,6,13,10,0,0,0
```

### Configuration B - Hybrid

```bash
source .venv/bin/activate
uvicorn api.server_config_b:app --port 8000
```

In another terminal:

```bash
source .venv/bin/activate
python -m api.client_hybrid --url http://127.0.0.1:8000 --features 0,0,5,13,9,1,0,0,0,0,13,15,10,15,5,0,0,3,15,2,0,11,8,0,0,4,12,0,0,8,8,0,0,5,8,0,0,9,8,0,0,4,11,0,1,12,7,0,0,2,14,5,10,12,0,0,0,0,6,13,10,0,0,0
```

### Configuration C - Full PQC

```bash
source .venv/bin/activate
uvicorn api.server_config_c:app --port 8000
```

In another terminal:

```bash
source .venv/bin/activate
python -m api.client_full_pqc --url http://127.0.0.1:8000 --features 0,0,5,13,9,1,0,0,0,0,13,15,10,15,5,0,0,3,15,2,0,11,8,0,0,4,12,0,0,8,8,0,0,5,8,0,0,9,8,0,0,4,11,0,1,12,7,0,0,2,14,5,10,12,0,0,0,0,6,13,10,0,0,0
```

## Benchmarking

For each run, start the matching server and run the benchmark command from a second terminal. The runner writes one raw record per request containing RTT, handshake time, reported server crypto time, process CPU snapshot, RSS snapshot, and any error.

Example: Configuration C at concurrency 10:

```bash
python -m bench.runner \
  --configuration full-pqc \
  --concurrency 10 \
  --requests 100 \
  --repetition 1 \
  --output results/raw/full-pqc-c10-r1.csv
```

Use these server/configuration pairs:

| Server module | Runner value |
| --- | --- |
| `api.server:app` | `control` |
| `api.server_config_a:app` | `classical` |
| `api.server_config_b:app` | `hybrid` |
| `api.server_config_c:app` | `full-pqc` |

### Required final sweep

The final experimental matrix is configurations A/B/C, concurrency 10/100/1000, and five repetitions per cell. Start conservatively with 100 requests per cell; increase the request count only after confirming the host remains stable at concurrency 1000. Keep the machine, Python environment, server command, and input vector fixed across all cells.

Name files consistently, for example:

```text
results/raw/classical-c100-r3.csv
results/raw/hybrid-c100-r3.csv
results/raw/full-pqc-c100-r3.csv
```

## Plot the current results

Generate the aggregate chart from all raw CSV files:

```bash
python -m analysis.plot_metrics
```

This writes `outputs/benchmark-comparison.png` with mean and standard-deviation error bars for protected-request RTT, handshake time, and reported server crypto plus inference time. To plot selected files only:

```bash
python -m analysis.plot_metrics \
  --input results/raw/classical-c10-r1.csv results/raw/full-pqc-c10-r1.csv \
  --output outputs/c10-comparison.png
```

Treat the current graph as a smoke-test visualization, not a final finding: it is based on a limited set of runs, and overlapping error bars mean small differences are not yet statistically meaningful.

## Final project goal and next steps

The final deliverable is a reproducible security-performance decision framework for AI APIs, aligned with the Review 1 proposal:

1. Complete the A/B/C benchmark matrix at 10, 100, and 1000 concurrency with five repetitions per cell.
2. Aggregate raw results into mean, median, standard deviation, p95, and p99 latency; report CPU and memory bounds alongside network/crypto bytes.
3. Implement the HNDL experiment: capture protected traffic for 1000 requests, measure stored byte growth by configuration, and distinguish ciphertext volume from quantum decryptability.
4. Implement the MITM experiment: tamper with protected responses, verify rejection by each client, and record tamper-detection latency.
5. Add the larger-payload sensitivity workload (the proposed CIFAR-10 CNN or equivalent) to test whether findings hold beyond the 64-feature digit model.
6. Build the weighted trade-off matrix combining security rating, normalized latency overhead, CPU, memory, and byte overhead; use it to recommend a migration strategy for each workload profile.
7. Package the final experiment with Docker and a reproducibility checklist for the intended open-source release.

## Security scope

These cryptographic wrappers are an application-layer benchmarking harness, not a replacement for TLS. In a real deployment, run the API behind authenticated TLS and use authenticated server-key distribution or certificate pinning. The handshake endpoints in this prototype intentionally expose ephemeral public key material so that the benchmark can measure fresh exchanges.
