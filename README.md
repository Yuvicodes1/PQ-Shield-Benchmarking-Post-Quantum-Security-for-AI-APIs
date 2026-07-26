# PQ-Shield

An empirical benchmarking framework for comparing classical, hybrid, and post-quantum protection of a latency-sensitive AI inference API.

## Completed foundation

This initial implementation covers the first two build phases:

- A deterministic Random Forest digit-classifier workload (64 input features).
- A plain FastAPI control endpoint at `POST /predict`.
- A classical protected endpoint at `POST /secure/predict` using RSA-2048/OAEP key transport, AES-256-GCM payload encryption, and ECDSA P-256 response signatures.
- A reusable secure client, protocol primitives, and round-trip tests.

The crypto designs are **benchmark wrappers**, not a replacement for TLS. Run the API behind TLS in any real deployment. The server's ephemeral RSA key is intentionally transported by `GET /secure/handshake`; production key distribution requires authenticated TLS and a certificate/pinning strategy.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m model.train
uvicorn api.server:app --reload --port 8000
```

In another terminal:

```bash
python -m api.client --url http://127.0.0.1:8000 --features 0,0,5,13,9,1,0,0,0,0,13,15,10,15,5,0,0,3,15,2,0,11,8,0,0,4,12,0,0,8,8,0,0,5,8,0,0,9,8,0,0,4,11,0,1,12,7,0,0,2,14,5,10,12,0,0,0,0,6,13,10,0,0,0
```

## Layout

```
model/       training script and generated model artifact
api/         plain control server, protected server, reusable client
crypto/      protocol interface and Configuration A implementation
tests/       unit and end-to-end tests for the classical path
```

## Next milestones

1. Add `config_b_hybrid.py` (ML-KEM-768 + ECDSA) and `config_c_full_pqc.py` (ML-KEM-768 + ML-DSA-65) using `liboqs-python`.
2. Add reproducible load sweeps (10/100/1000 concurrency, five repetitions), metrics capture, HNDL/MITM harnesses, and analysis matrix.

## Configuration B - Hybrid ML-KEM

Configuration B uses ML-KEM-768 for post-quantum key establishment and ECDSA P-256 to sign responses. Build its local `liboqs` dependency once:

```bash
bash scripts/install_oqs.sh
uvicorn api.server_config_b:app --port 8000
python -m api.client_hybrid --url http://127.0.0.1:8000 --features 0,0,5,13,9,1,0,0,0,0,13,15,10,15,5,0,0,3,15,2,0,11,8,0,0,4,12,0,0,8,8,0,0,5,8,0,0,9,8,0,0,4,11,0,1,12,7,0,0,2,14,5,10,12,0,0,0,0,6,13,10,0,0,0
```

## First benchmark run

The server now preloads the model at startup, so cold-start loading does not distort request timings.

```bash
uvicorn api.server:app --port 8000
python -m bench.runner --configuration control --concurrency 10 --requests 100 \
  --output results/raw/control-c10-r1.csv
python -m bench.runner --configuration classical --concurrency 10 --requests 100 \
  --output results/raw/classical-c10-r1.csv
```
