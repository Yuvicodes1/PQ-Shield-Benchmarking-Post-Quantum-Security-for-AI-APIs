#!/usr/bin/env bash
# Launches the PQ-Shield interactive Streamlit dashboard.
#
# Usage: bash scripts/run_webapp.sh [port]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

PORT="${1:-9000}"

if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

if [ -z "${PQ_SHIELD_OQS_LIB:-}" ]; then
  echo "PQ_SHIELD_OQS_LIB is not set and no .env file was found."
  echo "Run scripts/install_oqs.sh first, or export PQ_SHIELD_OQS_LIB manually."
  exit 1
fi

.venv/bin/streamlit run app.py --server.port "${PORT}"
