# PQ-Shield reproducible build image.
#
# Builds liboqs from source (minimal ML-KEM-768 / ML-DSA-65 configuration),
# installs pinned Python dependencies, trains the model artifact, and runs
# the crypto self-test + pytest suite at build time so a broken image never
# ships. Intended for the open-source release described in the Review 1
# proposal's "Target Project Outcomes" (Dockerized reproducibility).
#
# Build:
#   docker build -t pq-shield .
#
# Run the control server:
#   docker run --rm -p 8000:8000 pq-shield uvicorn api.server:app --host 0.0.0.0 --port 8000
#
# Run a full benchmark sweep (writes results/ inside the container -- mount
# a volume to persist it on the host):
#   docker run --rm -v "$(pwd)/results:/app/results" pq-shield \
#       python -m bench.orchestrator --configs control,classical,hybrid,full-pqc \
#       --concurrency 10,100,1000 --repetitions 5

FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build libssl-dev git ca-certificates \
    python3 python3-venv python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Build liboqs first (rarely changes, so it caches independently of app code).
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git liboqs && \
    mkdir -p liboqs/build && cd liboqs/build && \
    cmake -GNinja \
        -DCMAKE_INSTALL_PREFIX=/app/oqs-prefix \
        -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DBUILD_SHARED_LIBS=ON \
        .. && \
    ninja -j"$(nproc)" && ninja install && \
    cd /app && rm -rf liboqs

COPY requirements.txt .
RUN python3 -m venv /app/.venv && \
    /app/.venv/bin/pip install --no-cache-dir --upgrade pip && \
    /app/.venv/bin/pip install --no-cache-dir -r requirements.txt

COPY . .
ENV PQ_SHIELD_OQS_LIB=/app/oqs-prefix/lib/liboqs.so
ENV PATH="/app/.venv/bin:${PATH}"

# Fail the build if the crypto adapter or the protocol test suite regress.
RUN python -m crypto.oqs_adapter && \
    python -m model.train && \
    python -m pytest -q

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app /app

ENV PQ_SHIELD_OQS_LIB=/app/oqs-prefix/lib/liboqs.so
ENV PATH="/app/.venv/bin:${PATH}"

EXPOSE 8000 8501
CMD ["uvicorn", "api.server:app", "--host", "0.0.0.0", "--port", "8000"]
# To run the Streamlit dashboard instead:
#   docker run --rm -p 8501:8501 pq-shield streamlit run app.py --server.port 8501 --server.address 0.0.0.0
