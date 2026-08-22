# PQ-Shield: Design & Implementation Document
### Benchmarking the Cost of Post-Quantum Cryptography for AI Inference APIs

Author: Yuvi | Status: Draft v1 | Target venue: IEEE Access / ACM CCS Workshop

---

## 1. Problem Statement & Motivation

Every production AI inference API (OpenAI, AWS SageMaker, Azure ML, on-prem Flask/FastAPI servers) is currently secured with classical public-key cryptography — RSA for key exchange, ECDSA for signing. Both are broken by Shor's algorithm on a sufficiently large fault-tolerant quantum computer. That computer does not exist yet, but the **harvest-now-decrypt-later (HNDL)** threat model means adversaries can record encrypted traffic today and decrypt it retroactively once quantum hardware matures. For AI APIs specifically, the traffic being harvested is not generic — it is model inputs, model outputs, and potentially proprietary model behavior signatures, which have a long confidentiality shelf-life (medical inference, financial models, defense applications).

NIST finalized its first PQC standards in August 2024: **ML-KEM** (FIPS 203, formerly Kyber) for key encapsulation and **ML-DSA** (FIPS 204, formerly Dilithium) for digital signatures. Migration guidance exists at the protocol level (TLS 1.3 hybrid key exchange, X.509 PQC certificates), but almost no empirical work asks: *what does this migration cost a real AI inference workload, in concrete milliseconds, bytes, and CPU, and is a hybrid migration path "good enough" compared to full PQC?*

**PQ-Shield closes that gap.** It is not a new cryptographic algorithm. It is an empirical measurement framework that places a real inference API inside three cryptographic configurations, subjects each to concrete attack scenarios, and produces a quantitative trade-off matrix a security architect could actually use to make a migration decision.

---

## 2. Theoretical Background

### 2.1 Why classical crypto breaks under quantum

- **RSA / ECDSA** rely on the hardness of integer factorization and the discrete logarithm problem (including elliptic-curve discrete log). Shor's algorithm solves both in polynomial time on a quantum computer, collapsing their security to zero once a large enough error-corrected quantum computer exists.
- **ML-KEM (Kyber)** is built on the Module Learning-With-Errors (M-LWE) problem, a lattice problem believed to be hard even for quantum computers (no known quantum algorithm gives more than a modest — Grover-style — quadratic speedup against well-chosen parameters).
- **ML-DSA (Dilithium)** is also lattice-based (Module-LWE / Module-SIS), giving quantum-resistant signatures with a very different performance profile from ECDSA: larger keys and signatures, but fast sign/verify operations.

### 2.2 Why "hybrid" exists as a migration category

Standards bodies (IETF, NIST) currently recommend **hybrid key exchange** (classical + PQC combined, e.g., X25519 + ML-KEM-768) rather than jumping straight to PQC-only, because:
1. PQC algorithms are newer and have less cryptanalytic scrutiny than RSA/ECC.
2. Hybrid schemes are secure as long as *either* the classical or the PQC component holds — a hedge against undiscovered lattice attacks.
3. It gives organizations an incremental migration path without a "flag day" cutover.

This is why Configuration B (Hybrid) is not a strawman in this project — it's the industry's actual recommended default for the next several years, and measuring it in an AI-specific context is a legitimate and useful data point, separate from Configuration C (Full PQC, which some highly sensitive deployments will still want for symmetric long-term protection guarantees on signing).

### 2.3 Why AI inference APIs are a distinct measurement target

Generic PQC-in-TLS benchmarks (there are several published ones) measure handshake cost on arbitrary payloads. An AI inference API has a specific traffic shape that changes the economics:
- **Payload size asymmetry**: requests are often small (a feature vector, a short prompt) while responses can be larger (logits, class probabilities, generated text) — so the relative overhead of PQC ciphertext/signature bytes is proportionally much larger than in a bulk-data TLS session.
- **High request rate / low per-request latency budget**: inference APIs are latency-SLA-bound (often <100ms p99 targets), so a crypto handshake overhead that is negligible for a browser page load can be a meaningful fraction of an inference SLA.
- **Repeated connections at scale**: many inference clients (mobile apps, edge devices, other services) open frequent short-lived connections rather than long persistent ones, so handshake cost is paid more often relative to payload transferred.

This is the empirical gap PQ-Shield fills: nobody has measured PQC overhead *as a fraction of an inference request's total latency budget*, under realistic concurrency, against AI-relevant attack scenarios.

---

## 3. Hypotheses

Each hypothesis maps directly to one research question (RQ1–RQ4) and is falsifiable by the benchmark data you will collect.

| # | Hypothesis | Maps to |
|---|---|---|
| **H1** | Full PQC (Config C) adds measurable but bounded latency overhead versus classical RSA/ECDSA (Config A) at low concurrency (10 req), and this overhead grows *sub-linearly* relative to request volume as concurrency increases to 1,000, because handshake cost amortizes while per-request signature cost dominates. | RQ1 |
| **H2** | Hybrid (Config B) captures the majority (hypothesized >85%) of Full PQC's quantum-resistance benefit for the *key exchange* attack surface (HNDL) while incurring less than half of Full PQC's total latency overhead, because ECDSA signing (kept in Config B) is cheaper than ML-DSA signing. | RQ2 |
| **H3** | The HNDL-relevant ciphertext volume per request is larger for ML-KEM-768 than RSA-2048 in raw bytes (ML-KEM ciphertexts ≈1088 bytes vs. RSA-2048 ≈256 bytes), meaning naive "bytes stored by attacker" *increases* under PQC — but the *decryptability* of that stored data drops to zero under quantum assumptions, so the meaningful metric is "expected present-value of harvested data," not raw bytes. RQ3's contribution is making this distinction explicit and quantifying both. | RQ3 |
| **H4** | ML-DSA-65 signature verification is faster in wall-clock time than ECDSA (P-256) verification (lattice-based verification is typically cheap arithmetic vs. elliptic-curve point operations), so MITM tamper-detection latency is *not worse*, and may be *better*, under Full PQC — meaning the signature-scheme choice is not a barrier to adoption even under active-attacker conditions. | RQ4 |

State plainly in the paper: **H3 and H4 are the "surprising" hypotheses** — most people assume PQC is strictly worse on every axis. If your data confirms H3/H4's nuance (bigger ciphertexts but categorically different security; verification not necessarily slower), that nuance is your most citable finding. If your data *contradicts* a hypothesis, that is still a valid and reportable result — write the paper around what you actually measure, not around confirming these priors.

---

## 4. System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client / Load Generator                   │
│              (locust or custom asyncio client, N concurrent)     │
└───────────────────────────┬───────────────────────────────────────┘
                             │ HTTP(S) — instrumented
┌───────────────────────────▼───────────────────────────────────────┐
│                     Layer 3: Crypto Wrapper                       │
│   Config A: RSA-2048 KEX + ECDSA-P256 sign  (classical.py)        │
│   Config B: ML-KEM-768 KEX + ECDSA-P256 sign (hybrid.py)          │
│   Config C: ML-KEM-768 KEX + ML-DSA-65 sign  (full_pqc.py)        │
│   — implemented as FastAPI middleware / dependency injection —    │
└───────────────────────────┬───────────────────────────────────────┘
                             │
┌───────────────────────────▼───────────────────────────────────────┐
│                Layer 2: FastAPI Inference Server                  │
│                    POST /predict  (single endpoint)                │
└───────────────────────────┬───────────────────────────────────────┘
                             │
┌───────────────────────────▼───────────────────────────────────────┐
│              Layer 1: Model (sklearn RF or PyTorch CNN)            │
│                     loaded once at startup, in-memory              │
└─────────────────────────────────────────────────────────────────┘

        ┌────────────────────────┐      ┌───────────────────────────┐
        │ Threat Scenario 1: HNDL │      │ Threat Scenario 2: MITM   │
        │ passive capture script  │      │ mitmproxy tamper harness  │
        │ (scapy / raw socket dump)│     │ (local addon script)      │
        └────────────────────────┘      └───────────────────────────┘
                             │                        │
┌───────────────────────────▼────────────────────────▼───────────────┐
│         Layer 5: Benchmark Engine (orchestrator.py)                │
│   sweeps: {config A,B,C} × {concurrency 10,100,1000} × {threat 1,2}│
│   collects: handshake_ms, rtt_ms, key_bytes, sig_bytes, cpu%, mem_MB│
│   → raw_results/*.csv                                              │
└───────────────────────────┬───────────────────────────────────────┘
                             │
┌───────────────────────────▼───────────────────────────────────────┐
│      Layer 6: Analysis (pandas) → Trade-off Matrix (matplotlib)    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Repository Structure

```
pq-shield/
├── README.md                      # reproducibility instructions (write last, week 16)
├── pyproject.toml / requirements.txt
├── model/
│   ├── train_model.py              # trains + serializes RF or CNN
│   └── artifacts/model.pkl
├── server/
│   ├── app.py                      # FastAPI app, /predict endpoint
│   ├── crypto/
│   │   ├── classical.py            # Config A: RSA-2048 + ECDSA
│   │   ├── hybrid.py                # Config B: ML-KEM-768 + ECDSA
│   │   ├── full_pqc.py              # Config C: ML-KEM-768 + ML-DSA-65
│   │   └── base.py                  # shared interface (KEX + sign/verify contract)
│   └── instrumentation.py          # psutil + tracemalloc wrappers, timing decorators
├── client/
│   └── load_client.py              # async client, configurable concurrency
├── threats/
│   ├── hndl_capture.py              # Threat Scenario 1
│   └── mitm_harness.py              # Threat Scenario 2 (mitmproxy addon)
├── benchmark/
│   ├── orchestrator.py             # runs the full sweep, writes CSVs
│   └── config.yaml                  # concurrency levels, repetitions, configs to test
├── analysis/
│   ├── aggregate.py                 # raw CSV → summary stats (mean, std, CI)
│   ├── tradeoff_matrix.py          # builds composite score matrix (Layer 6)
│   └── figures.py                   # generates all paper figures
├── raw_results/                     # gitignored, CSVs land here
├── figures/                         # gitignored, PNG/SVG output
└── paper/
    └── pq_shield.tex (or .md)      # IEEE Access / ACM template
```

---

## 6. Step-by-Step Implementation Guide

### Phase 0 — Environment Setup (before Week 1 officially starts)

```bash
# System dependencies for liboqs (build from source is most reliable)
sudo apt update && sudo apt install -y build-essential cmake ninja-build \
    libssl-dev python3-dev git

# Build liboqs (the C library pyoqs binds to)
git clone --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja
sudo ninja install
sudo ldconfig

# Python environment
python3 -m venv venv && source venv/bin/activate
pip install liboqs-python   # official pyoqs bindings package name
pip install fastapi uvicorn[standard] cryptography scikit-learn torch torchvision \
    pandas matplotlib psutil mitmproxy httpx locust pytest pyyaml
```

**Verification step (do this before writing any project code):**
```python
import oqs
print(oqs.get_enabled_KEM_mechanisms())   # should list Kyber512/768/1024 or ML-KEM-768
print(oqs.get_enabled_sig_mechanisms())    # should list Dilithium3 or ML-DSA-65
```
If `ML-KEM-768` / `ML-DSA-65` don't appear by the standardized name, use whatever the library's current alias is (older liboqs builds may still expose them as `Kyber768` / `Dilithium3` — same algorithms, pre-standardization naming). Note the exact string you use in your paper's reproducibility appendix.

---

### Phase 1 — Weeks 1–3: Foundation

**Step 1.1 — Train and serialize the model**
```python
# model/train_model.py
from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import load_digits  # or swap for CIFAR-10 CNN later
from sklearn.model_selection import train_test_split
import joblib

X, y = load_digits(return_X_y=True)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)
print("test accuracy:", clf.score(X_test, y_test))
joblib.dump(clf, "model/artifacts/model.pkl")
```
Start with `load_digits` (small, fast, zero download friction) to get the whole pipeline working end to end. Swap to CIFAR-10 + a small CNN in Week 2 once the API skeleton works — model accuracy is explicitly not the point, but you want a second, larger model to show your overhead numbers hold across payload sizes (a CNN's output is 10-way softmax same as RF here, but you can also test a larger embedding-output model later if you want a payload-size sensitivity result as a bonus figure).

**Step 1.2 — Bare FastAPI endpoint (no crypto yet)**
```python
# server/app.py (v0, unsecured)
from fastapi import FastAPI
import joblib, numpy as np
from pydantic import BaseModel

app = FastAPI()
model = joblib.load("model/artifacts/model.pkl")

class PredictRequest(BaseModel):
    features: list[float]

@app.post("/predict")
def predict(req: PredictRequest):
    x = np.array(req.features).reshape(1, -1)
    pred = model.predict(x)[0]
    proba = model.predict_proba(x)[0].tolist()
    return {"prediction": int(pred), "probabilities": proba}
```
```bash
uvicorn server.app:app --reload --port 8000
curl -X POST localhost:8000/predict -H "Content-Type: application/json" \
  -d '{"features":[0,0,5,13,9,1,0,0,0,0,13,15,10,15,5,0,0,3,15,2,0,11,8,0,0,4,12,0,0,8,8,0,0,5,8,0,0,9,8,0,0,4,11,0,1,12,7,0,0,2,14,5,10,12,0,0,0,0,6,13,10,0,0,0]}'
```
End of Phase 1 checkpoint: unsecured API returns predictions with correct latency baseline (~5–15ms). Record this baseline — it's your "zero overhead" floor for later comparisons.

---

### Phase 2 — Weeks 4–6: Configuration A (Classical Baseline)

Design contract shared by all three configs (write this interface first so B and C are drop-in swaps):

```python
# server/crypto/base.py
from abc import ABC, abstractmethod

class CryptoConfig(ABC):
    @abstractmethod
    def generate_keys(self) -> dict: ...          # returns {"public":..., "private":...}, records byte sizes

    @abstractmethod
    def key_exchange(self, peer_public) -> bytes: ... # returns shared secret, records handshake_ms

    @abstractmethod
    def sign(self, message: bytes) -> bytes: ...        # returns signature, records sig_bytes

    @abstractmethod
    def verify(self, message: bytes, signature: bytes, public_key) -> bool: ...
```

```python
# server/crypto/classical.py
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
import time

class ClassicalConfig:
    def __init__(self):
        self.rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec_private = ec.generate_private_key(ec.SECP256R1())

    def generate_keys(self):
        t0 = time.perf_counter()
        pub = self.rsa_private.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"public": pub, "key_bytes": len(pub), "gen_ms": (time.perf_counter()-t0)*1000}

    def key_exchange(self, peer_public_pem):
        # RSA is used here for key transport (encrypt a random session key with RSA-OAEP),
        # which is the realistic classical analogue to a KEM.
        t0 = time.perf_counter()
        session_key = os.urandom(32)
        peer_pub = serialization.load_der_public_key(peer_public_pem)
        ciphertext = peer_pub.encrypt(
            session_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None))
        return {"shared_secret": session_key, "ciphertext": ciphertext,
                "ciphertext_bytes": len(ciphertext), "handshake_ms": (time.perf_counter()-t0)*1000}

    def sign(self, message: bytes):
        t0 = time.perf_counter()
        sig = self.ec_private.sign(message, ec.ECDSA(hashes.SHA256()))
        return {"signature": sig, "sig_bytes": len(sig), "sign_ms": (time.perf_counter()-t0)*1000}

    def verify(self, message, signature, public_key):
        t0 = time.perf_counter()
        try:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            ok = True
        except Exception:
            ok = False
        return {"valid": ok, "verify_ms": (time.perf_counter()-t0)*1000}
```

Wrap this into FastAPI as a dependency that runs on every `/predict` call: client fetches server's public key on first contact (simulate a fresh handshake per request by default — this is your worst-case / most conservative benchmark; note in the paper that connection reuse would amortize this further, and optionally add a "warm connection" variant as a secondary result).

**Checkpoint:** every request to `/predict` is now signed and verified end-to-end with Config A; log handshake_ms, sign_ms, verify_ms, sig_bytes, key_bytes to a CSV via `instrumentation.py`.

---

### Phase 3 — Weeks 7–9: Configurations B and C (PQC)

```python
# server/crypto/hybrid.py  (Config B: ML-KEM-768 KEX + ECDSA sign)
import oqs, time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

class HybridConfig:
    KEM_ALG = "ML-KEM-768"   # fall back to "Kyber768" if your liboqs build predates the rename

    def __init__(self):
        self.kem = oqs.KeyEncapsulation(self.KEM_ALG)
        self.ec_private = ec.generate_private_key(ec.SECP256R1())  # signing stays classical

    def generate_keys(self):
        t0 = time.perf_counter()
        pub = self.kem.generate_keypair()
        return {"public": pub, "key_bytes": len(pub), "gen_ms": (time.perf_counter()-t0)*1000}

    def key_exchange(self, peer_public):
        t0 = time.perf_counter()
        ciphertext, shared_secret = self.kem.encap_secret(peer_public)
        return {"shared_secret": shared_secret, "ciphertext": ciphertext,
                "ciphertext_bytes": len(ciphertext), "handshake_ms": (time.perf_counter()-t0)*1000}

    def sign(self, message: bytes):
        t0 = time.perf_counter()
        sig = self.ec_private.sign(message, ec.ECDSA(hashes.SHA256()))
        return {"signature": sig, "sig_bytes": len(sig), "sign_ms": (time.perf_counter()-t0)*1000}
    # verify() identical to ClassicalConfig.verify — reuse it
```

```python
# server/crypto/full_pqc.py  (Config C: ML-KEM-768 KEX + ML-DSA-65 sign)
import oqs, time

class FullPQCConfig:
    KEM_ALG = "ML-KEM-768"
    SIG_ALG = "ML-DSA-65"   # fall back to "Dilithium3" on older builds

    def __init__(self):
        self.kem = oqs.KeyEncapsulation(self.KEM_ALG)
        self.signer = oqs.Signature(self.SIG_ALG)

    def generate_keys(self):
        t0 = time.perf_counter()
        kem_pub = self.kem.generate_keypair()
        sig_pub = self.signer.generate_keypair()
        return {"kem_public": kem_pub, "sig_public": sig_pub,
                "key_bytes": len(kem_pub) + len(sig_pub),
                "gen_ms": (time.perf_counter()-t0)*1000}

    def key_exchange(self, peer_public):
        t0 = time.perf_counter()
        ciphertext, shared_secret = self.kem.encap_secret(peer_public)
        return {"shared_secret": shared_secret, "ciphertext": ciphertext,
                "ciphertext_bytes": len(ciphertext), "handshake_ms": (time.perf_counter()-t0)*1000}

    def sign(self, message: bytes):
        t0 = time.perf_counter()
        sig = self.signer.sign(message)
        return {"signature": sig, "sig_bytes": len(sig), "sign_ms": (time.perf_counter()-t0)*1000}

    def verify(self, message, signature, sig_public):
        t0 = time.perf_counter()
        ok = self.signer.verify(message, signature, sig_public)
        return {"valid": ok, "verify_ms": (time.perf_counter()-t0)*1000}
```

Wire both into `server/app.py` behind a `CRYPTO_CONFIG` environment variable (`classical|hybrid|full_pqc`) so the orchestrator can start the server fresh in each mode without code changes — this matters for reproducibility and for the benchmark automation in Phase 5.

**Checkpoint (end of Week 9):** three independently launchable server modes, each serving real `/predict` traffic with full crypto round-trips, each logging the six raw metrics from Layer 5 to CSV.

---

### Phase 4 — Weeks 10–11: Threat Simulation

**Threat 1 — HNDL capture script**
```python
# threats/hndl_capture.py
"""
Passively records N request/response pairs' cryptographic artifacts
(ciphertext, signature, key material) without decrypting anything —
simulating an adversary who stores traffic for future decryption.
"""
import httpx, csv, time

def capture(n_requests: int, endpoint: str, config_name: str, out_csv: str):
    rows = []
    with httpx.Client() as client:
        for i in range(n_requests):
            resp = client.post(endpoint, json={"features": SAMPLE_FEATURES})
            meta = resp.json().get("_crypto_meta", {})  # server should echo sizes in a debug field
            rows.append({
                "request_id": i,
                "config": config_name,
                "ciphertext_bytes": meta.get("ciphertext_bytes"),
                "signature_bytes": meta.get("sig_bytes"),
                "key_bytes": meta.get("key_bytes"),
                "total_bytes_stored": (meta.get("ciphertext_bytes",0)
                                        + meta.get("sig_bytes",0)
                                        + meta.get("key_bytes",0)),
            })
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader(); writer.writerows(rows)
    total = sum(r["total_bytes_stored"] for r in rows)
    print(f"{config_name}: {n_requests} requests, {total} bytes total, {total/n_requests:.1f} bytes/request")
```
Have `server/app.py` include a `_crypto_meta` debug field in responses **only when a `X-Debug-Metrics: true` header is present**, so production-shaped responses stay realistic while your benchmark client can still extract sizes — this is a methodologically honest way to instrument without polluting the "real" response payload you're measuring RTT on.

**Threat 2 — MITM tamper harness (mitmproxy addon)**
```python
# threats/mitm_harness.py
"""
mitmproxy addon: intercepts responses from /predict and flips a byte
in the prediction payload before forwarding to the client. The client
then runs signature verification and should reject the tampered response.
We time how long detection takes.
"""
import time, json
from mitmproxy import http

class TamperAddon:
    def response(self, flow: http.HTTPFlow):
        if "/predict" in flow.request.path:
            flow.metadata["tamper_start"] = time.perf_counter()
            body = json.loads(flow.response.get_text())
            if "prediction" in body:
                body["prediction"] = (body["prediction"] + 1) % 10  # flip the class
            flow.response.set_text(json.dumps(body))

addons = [TamperAddon()]
```
```bash
mitmdump -s threats/mitm_harness.py --listen-port 8080
# point load_client.py at localhost:8080 instead of 8000 directly during this threat run
```
The **client-side verify() call** (already instrumented in Phase 2/3 for verify_ms) is what actually detects the tamper — record verify_ms specifically for tampered vs. non-tampered runs and confirm the tampered response is rejected (verify returns `valid: False`) in every trial. This is the number that answers RQ4.

**Checkpoint:** you can demonstrate, end to end, that Config A/B/C all correctly reject a tampered response, and you have timestamped verify_ms for each.

---

### Phase 5 — Weeks 12–13: Benchmark Runs

```python
# benchmark/orchestrator.py
import subprocess, time, itertools, os, csv
from client.load_client import run_load

CONFIGS = ["classical", "hybrid", "full_pqc"]
CONCURRENCY_LEVELS = [10, 100, 1000]
REPETITIONS = 5

def start_server(config_name):
    env = os.environ.copy(); env["CRYPTO_CONFIG"] = config_name
    proc = subprocess.Popen(["uvicorn", "server.app:app", "--port", "8000"], env=env)
    time.sleep(2)  # warm-up
    return proc

def run_sweep():
    results = []
    for config, concurrency, rep in itertools.product(CONFIGS, CONCURRENCY_LEVELS, range(REPETITIONS)):
        proc = start_server(config)
        try:
            metrics = run_load(endpoint="http://localhost:8000/predict",
                                concurrency=concurrency, n_requests=concurrency * 10)
            metrics.update({"config": config, "concurrency": concurrency, "rep": rep})
            results.append(metrics)
        finally:
            proc.terminate(); proc.wait()
    with open("raw_results/sweep.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader(); writer.writerows(results)

if __name__ == "__main__":
    run_sweep()
```
Use `psutil.Process().cpu_percent(interval=1)` sampled every second during the load window and `tracemalloc.start()` / `tracemalloc.get_traced_memory()` around the crypto operations specifically (not the whole process) to isolate crypto-attributable memory overhead from model-inference memory. Run each (config × concurrency) cell **5 times minimum** as specified — this gives you enough samples for a t-test or Mann-Whitney U test between configs at each concurrency level, and lets you report 95% confidence intervals rather than single-run point estimates, which is what reviewers will look for first.

**Statistical rigor checklist for this phase:**
- Discard the first ~5% of requests in each run as JIT/cache warm-up, unless you're deliberately measuring cold-start.
- Report mean ± standard deviation AND median/p95/p99 — latency distributions are right-skewed, means alone are misleading for an SLA-relevant claim.
- Use a non-parametric test (Mann-Whitney U) rather than assuming normality for the A vs. B vs. C comparisons, given typical network/crypto latency distributions.
- Pin CPU frequency scaling / disable turbo boost if possible (or explicitly note you didn't, and treat CPU% numbers as relative-only, not absolute).

---

### Phase 6 — Weeks 14–15: Analysis & Trade-off Matrix

The composite score (Layer 6) needs an explicit, justified formula — don't hand-wave it, since RQ2 requires you to defend it. A reasonable starting point:

```
composite_score(config, concurrency) =
    w_sec * security_score(config) - w_perf * normalized_latency_overhead(config, concurrency)
```
where:
- `security_score` is a categorical/ordinal mapping you justify in the paper (e.g., Classical=0, Hybrid=0.8, Full PQC=1.0 — with the 0.8 for Hybrid justified by "quantum-resistant key exchange closes the HNDL threat entirely; only the signature layer remains classically vulnerable, and signatures only matter for real-time integrity, not confidentiality of harvested data" — this is a genuine judgment call you should defend explicitly, not assert).
- `normalized_latency_overhead` = `(rtt_ms[config] - rtt_ms[classical]) / rtt_ms[classical]`, computed per concurrency level.
- `w_sec`, `w_perf` are weights — report the matrix at 2–3 different weightings (security-priority, performance-priority, balanced) rather than picking one arbitrary weighting, so the reader can apply their own organizational risk tolerance. This is more defensible than a single hard-coded weighting and is a better fit for a workshop paper.

```python
# analysis/tradeoff_matrix.py (skeleton)
import pandas as pd

def build_matrix(df: pd.DataFrame, weightings: dict):
    baseline = df[df.config == "classical"].groupby("concurrency").rtt_ms.mean()
    df["overhead_pct"] = df.apply(
        lambda r: (r.rtt_ms - baseline[r.concurrency]) / baseline[r.concurrency], axis=1)
    security_scores = {"classical": 0.0, "hybrid": 0.8, "full_pqc": 1.0}
    rows = []
    for (config, concurrency), g in df.groupby(["config", "concurrency"]):
        for wname, (w_sec, w_perf) in weightings.items():
            score = w_sec * security_scores[config] - w_perf * g.overhead_pct.mean()
            rows.append({"config": config, "concurrency": concurrency,
                         "weighting": wname, "score": score})
    return pd.DataFrame(rows)
```

**Figures to generate (minimum set for the paper):**
1. RTT vs. concurrency, one line per config (log-x if concurrency spread is large) — answers RQ1 directly.
2. Bar chart: handshake_ms, sign_ms, verify_ms decomposed per config, at one representative concurrency level — shows *where* the overhead comes from.
3. Bytes-per-request stacked bar (key + ciphertext + signature) per config — answers RQ3's raw byte-cost side.
4. HNDL storage-volume-per-1000-requests table/bar, annotated with the "decryptability" caveat from H3.
5. MITM verify_ms box plot, tampered vs. untampered, per config — answers RQ4.
6. Trade-off matrix heatmap (config × concurrency, colored by composite score), one panel per weighting scheme — your Layer 6 headline figure.
7. CPU% and memory-overhead heatmaps across the same grid, as supporting evidence.

---

### Phase 7 — Week 16: Paper & Reproducibility

- Write up in IEEE Access two-column or ACM CCS workshop template (LaTeX). Structure: Abstract → Intro (motivation from §1–2 above) → Threat Model (§2.3 + threats/) → System Design (§4 architecture) → Methodology (§6, esp. statistical rigor checklist) → Results (RQ1–RQ4 in order, one subsection each) → Discussion (where H1–H4 held / didn't) → Limitations → Related Work → Conclusion.
- **Limitations section — write this honestly, it strengthens rather than weakens the paper:** single-machine benchmarking (no real network latency/jitter), one hardware profile, liboqs implementations may not reflect all vendors' PQC implementations, model choice (RandomForest/CNN) doesn't stress payload size the way an LLM API would (flag this explicitly as future work if you don't have time to add an LLM-scale payload variant).
- README.md needs: exact liboqs/pyoqs version pinned, exact algorithm name strings used (ML-KEM-768 vs Kyber768 naming), hardware spec the numbers were collected on, one-command reproduction script (`make benchmark` or `bash run_all.sh`), and a note that absolute numbers are hardware-dependent but *relative* overhead ratios between configs should reproduce.
- Release repo under MIT or Apache-2.0 license; open-source release with clean reproducibility is explicitly called out as a strength for this venue.

---

## 7. Data Gathering Summary Table

| Data artifact | Collected by | When | Used for |
|---|---|---|---|
| `raw_results/sweep.csv` | `benchmark/orchestrator.py` | Weeks 12–13 | RQ1, RQ2 (latency, CPU, memory) |
| `hndl_capture_{config}.csv` | `threats/hndl_capture.py` | Week 10–11 | RQ3 (byte volume) |
| `mitm_verify_times.csv` | `threats/mitm_harness.py` + client verify logging | Week 10–11 | RQ4 (detection latency) |
| `aggregate_stats.csv` | `analysis/aggregate.py` | Week 14 | Means/CIs feeding all figures |
| `tradeoff_matrix.csv` | `analysis/tradeoff_matrix.py` | Week 15 | Layer 6 headline figure |

---

## 8. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| `liboqs`/`pyoqs` build fails on your OS/architecture | Use the official Docker image (`openquantumsafe/oqs-python`) as a fallback dev environment rather than fighting a native build. |
| Benchmark noise from running on a shared/laptop machine (thermal throttling, background processes) | Report relative overhead (% vs. classical baseline) as the primary result, absolute ms as secondary; note hardware limitations explicitly in Limitations. |
| Algorithm naming churn (Kyber→ML-KEM, Dilithium→ML-DSA across liboqs versions) | Pin the exact liboqs version in `requirements.txt`/README on day 1; print and log the exact mechanism string your code resolves to at runtime. |
| Composite score in Layer 6 looks arbitrary to reviewers | Report multiple weightings (§Phase 6) instead of one number; explicitly justify the security_score ordinal mapping in prose. |
| 1,000-concurrency level saturates a single laptop rather than testing the crypto | Monitor and report baseline (Config A at 1000 concurrency) resource ceiling first — if the *unsecured* API already saturates CPU at 1000, note that the 1000-level results measure "overhead under contention" rather than "overhead in isolation," which is still a valid and reportable finding, just frame it correctly. |

---

## 9. Definition of Done (per phase)

- **Phase 1:** `curl` returns a correct prediction from the bare API in <20ms p50.
- **Phase 2:** Config A round-trips a signed request and rejects a manually corrupted signature.
- **Phase 3:** Config B and C both round-trip successfully; `oqs.get_enabled_KEM_mechanisms()`/`sig_mechanisms()` confirm you're using the exact standardized algorithm strings you cite in the paper.
- **Phase 4:** HNDL script produces a populated CSV for all 3 configs; MITM harness demonstrably triggers a `valid: False` on 100% of tampered trials across all 3 configs.
- **Phase 5:** `raw_results/sweep.csv` has 3 configs × 3 concurrency levels × 5 reps = 45 rows minimum, each with all 6 metrics populated, no NaNs.
- **Phase 6:** All 7 figures generated and visually sane (no negative latencies, no config with zero overhead by construction error).
- **Phase 7:** A stranger with only the README can clone the repo and reproduce the relative-overhead ordering between configs (not necessarily identical absolute numbers) on their own machine.

---

## 10. Immediate Next Actions (start here)

1. Run the Phase 0 environment setup and confirm `import oqs` works with ML-KEM-768/ML-DSA-65 (or their pre-standard aliases) enumerated.
2. Scaffold the repo structure from §5 with empty stub files, `git init`, first commit.
3. Implement Phase 1 (Steps 1.1–1.2) and get the unsecured `/predict` endpoint returning predictions.
4. Once that's green, move to Phase 2 (Config A) — do not parallelize B/C ahead of A; A is the reference implementation everything else is measured against, and bugs there invalidate every later number.
