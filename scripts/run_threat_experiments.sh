#!/usr/bin/env bash
# Runs the HNDL capture and MITM tamper-detection experiments for a single
# configuration against an already-running secure server.
#
# Usage:
#   bash scripts/run_threat_experiments.sh classical 8001
#   bash scripts/run_threat_experiments.sh hybrid 8002
#   bash scripts/run_threat_experiments.sh full-pqc 8003
#
# Expects the matching server already running on the given port, e.g.:
#   uvicorn api.server_config_a:app --port 8001   (for "classical")

set -euo pipefail

CONFIG="${1:?Usage: run_threat_experiments.sh <classical|hybrid|full-pqc> <server_port>}"
PORT="${2:?Usage: run_threat_experiments.sh <classical|hybrid|full-pqc> <server_port>}"
PROXY_PORT="$((PORT + 1000))"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

mkdir -p results/hndl results/mitm

echo "=== HNDL capture: ${CONFIG} (1000 requests) ==="
.venv/bin/python -m threats.hndl_capture \
  --configuration "${CONFIG}" \
  --url "http://127.0.0.1:${PORT}" \
  --requests 1000 \
  --output "results/hndl/${CONFIG}-hndl.csv"

echo
echo "=== Starting MITM tamper proxy on :${PROXY_PORT} -> :${PORT} ==="
.venv/bin/python -m threats.mitm_harness \
  --upstream "http://127.0.0.1:${PORT}" \
  --listen-port "${PROXY_PORT}" \
  --tamper-target ciphertext \
  > "/tmp/mitm_proxy_${CONFIG}_ciphertext.log" 2>&1 &
PROXY_PID=$!
sleep 1.5

echo "=== MITM experiment: ${CONFIG} (tamper-target=ciphertext) ==="
.venv/bin/python -m threats.mitm_experiment \
  --configuration "${CONFIG}" \
  --proxy-url "http://127.0.0.1:${PROXY_PORT}" \
  --requests 100 \
  --tamper-target ciphertext \
  --output "results/mitm/${CONFIG}-mitm-ciphertext.csv"

kill "${PROXY_PID}" 2>/dev/null || true
sleep 1

echo
echo "=== Starting MITM tamper proxy on :${PROXY_PORT} -> :${PORT} (signature target) ==="
.venv/bin/python -m threats.mitm_harness \
  --upstream "http://127.0.0.1:${PORT}" \
  --listen-port "${PROXY_PORT}" \
  --tamper-target signature \
  > "/tmp/mitm_proxy_${CONFIG}_signature.log" 2>&1 &
PROXY_PID=$!
sleep 1.5

echo "=== MITM experiment: ${CONFIG} (tamper-target=signature) ==="
.venv/bin/python -m threats.mitm_experiment \
  --configuration "${CONFIG}" \
  --proxy-url "http://127.0.0.1:${PROXY_PORT}" \
  --requests 100 \
  --tamper-target signature \
  --output "results/mitm/${CONFIG}-mitm-signature.csv"

kill "${PROXY_PID}" 2>/dev/null || true

echo
echo "Done. Results in results/hndl/ and results/mitm/"
