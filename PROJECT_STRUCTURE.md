# PQ-Shield Project Structure

This document explains the role of every project folder and implementation
file. It complements the setup and usage instructions in `README.md`.

## Top-level files

| Path | Purpose |
| --- | --- |
| `README.md` | Project overview, security scope, setup commands, and examples for the API and benchmark runner. |
| `PROJECT_STRUCTURE.md` | This folder-and-file implementation guide. |
| `requirements.txt` | Pinned compatibility ranges for the API, cryptography, ML, HTTP, and test dependencies. |
| `pytest.ini` | Configures pytest to discover tests in `tests/` and omit the local virtual environment and `work/` directory. |

## Folders at a glance

```text
api/       FastAPI applications, request/response schemas, clients, and inference service
bench/     Asynchronous benchmark runner and CSV metric writer
crypto/    Classical and hybrid protected-channel implementations
model/     Training code and the persisted digit-classifier artifact
scripts/   Local development/dependency installation scripts
tests/     Classical and hybrid protocol/API tests
results/   Raw benchmark output CSV files
outputs/   Reserved location for derived experiment outputs
work/      Local, generated dependency builds and supporting working assets
```

## `api/` — HTTP API and client implementations

| File | Implementation |
| --- | --- |
| `__init__.py` | Marks the directory as the API package. |
| `schemas.py` | Defines the shared Pydantic models: a request containing exactly 64 numeric digit features, and a prediction response containing the class, probabilities, and inference duration. |
| `service.py` | Central inference path. Lazily loads `model/artifacts/model.pkl`, converts input features to a `1 × 64` NumPy matrix, executes the model, and returns a typed response. All protection configurations use this same function so cryptography does not change model behavior. |
| `server.py` | Combined control application. Exposes the unprotected `/predict` endpoint and re-exports Configuration A protected routes for side-by-side benchmarking. Its lifespan hook preloads the model so model deserialization is excluded from request timings. |
| `server_config_a.py` | Standalone Configuration A API. It creates a `ClassicalChannel`, publishes handshake material, decrypts protected requests, runs inference, then encrypts and signs protected responses. |
| `server_config_b.py` | Standalone Configuration B API. It follows the same request/inference/response flow as Configuration A but uses the ML-KEM hybrid channel. |
| `client.py` | Command-line and reusable Configuration A client. It obtains RSA and ECDSA public keys, generates an AES session key, encrypts the request, verifies the response signature, decrypts the response, and returns the result. |
| `client_hybrid.py` | Command-line and reusable Configuration B client. It encapsulates an ML-KEM-768 shared secret, then uses that secret for the AES-GCM request and response exchange while retaining ECDSA response verification. |

## `crypto/` — protected-channel implementations

| File | Implementation |
| --- | --- |
| `__init__.py` | Marks this directory as the swappable cryptographic-configuration package. |
| `channel.py` | Declares the intended common channel abstraction and handshake data structure for crypto configurations. It documents the expected operations for future configurations. |
| `config_a_classical.py` | Implements Configuration A: per-request RSA-2048/OAEP transport of a 32-byte AES-256 key, AES-GCM payload envelopes, and ECDSA P-256 signatures over encrypted responses. It also contains Base64 and envelope helpers shared by clients and benchmark code. |
| `config_b_hybrid.py` | Implements Configuration B: ML-KEM-768 establishes the 32-byte shared secret, AES-GCM protects payloads, and ECDSA P-256 signs encrypted responses. |
| `oqs_kem.py` | Provides a small `ctypes` adapter around locally built `liboqs`, exposing only ML-KEM-768 key generation, encapsulation, and decapsulation. It finds the library under `work/oqs-prefix/` or through `PQ_SHIELD_OQS_LIB`. |

## `model/` — inference workload

| File or folder | Implementation |
| --- | --- |
| `__init__.py` | Marks the model directory as a package. |
| `train.py` | Loads scikit-learn's 64-feature handwritten-digits dataset, trains a deterministic 100-tree `RandomForestClassifier`, and saves it with Joblib. |
| `artifacts/` | Stores generated model artifacts used at runtime. |
| `artifacts/model.pkl` | The persisted random-forest model loaded by `api/service.py`. Regenerate it with `python -m model.train`. |

## `bench/` — benchmark collection

| File | Implementation |
| --- | --- |
| `__init__.py` | Marks the benchmarking directory as a package. |
| `metrics.py` | Defines one raw metric record per request and writes records as CSV, creating the target directory when needed. |
| `runner.py` | Runs concurrent asynchronous requests against the control or Configuration A API. It measures request round-trip time, handshake time, reported server crypto time, process CPU/RSS snapshots, and failures. |

## `tests/` — verification

| File | What it verifies |
| --- | --- |
| `test_classical_roundtrip.py` | Invalid classical ciphertext is rejected; the control app serves the secure handshake; and a Configuration A request completes with a valid signed, decryptable prediction. |
| `test_hybrid_kem.py` | ML-KEM-768 key establishment produces matching shared secrets and validates key sizes. |
| `test_hybrid_roundtrip.py` | A full Configuration B request completes with an ECDSA-verifiable, AES-GCM-decryptable prediction. |

## Generated and support folders

| Folder or file | Purpose |
| --- | --- |
| `scripts/install_oqs.sh` | Clones `liboqs` into `work/liboqs`, builds only ML-KEM-768 as a shared library, and installs it locally under `work/oqs-prefix`. It does not perform a system-wide installation. |
| `results/raw/` | Stores benchmark CSV output. Existing `control-c10-r1.csv` and `classical-c10-r1.csv` are sample runs at concurrency 10, repetition 1. |
| `outputs/` | Reserved for derived charts, reports, or other experiment deliverables; it is currently empty. |
| `work/liboqs/` | Local clone of the third-party Open Quantum Safe `liboqs` source tree. |
| `work/liboqs-min-build/` and `work/liboqs-build/` | CMake build directories created while compiling `liboqs`; they contain generated build products and metadata. |
| `work/oqs-prefix/` | Local installation prefix containing the `liboqs` dynamic library and headers used by `crypto/oqs_kem.py`. |
| `work/liboqs-python/` | Local checkout/build workspace for the optional Python bindings, if present. The current implementation uses `ctypes` instead. |
| `work/pdfs/` | Rendered image assets from supporting project material; these do not participate in API execution. |
| `.venv/`, `__pycache__/`, and `.pytest_cache/` | Local interpreter, Python bytecode, and pytest caches. They are generated development state, not application source. |

## Request flow

1. A client requests `/secure/handshake` and receives public key material.
2. The client establishes or transports a fresh 32-byte AES session key, then AES-GCM encrypts the JSON feature payload.
3. The protected server decrypts the request, validates the 64 features, and calls the shared `api.service.predict` implementation.
4. The server AES-GCM encrypts the prediction with the same session key and signs the encrypted response with ECDSA P-256.
5. The client verifies the signature before decrypting the response.

Configuration A uses RSA-OAEP in step 2; Configuration B uses ML-KEM-768 encapsulation. These mechanisms are benchmark wrappers and are intended to run behind authenticated TLS in a real deployment.
