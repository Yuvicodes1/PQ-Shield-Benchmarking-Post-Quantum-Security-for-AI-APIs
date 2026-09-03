#!/usr/bin/env bash
# Run this the morning of your demo. Checks everything the live demo
# depends on and prints a clear PASS/FAIL for each, so nothing surprises
# you in front of the panel.
#
# Usage: bash scripts/preflight_check.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

PASS="✅"
FAIL="❌"
WARN="⚠️ "
EXIT_CODE=0

check() {
  local description="$1"
  local status="$2"  # 0 = pass, 1 = fail, 2 = warn
  if [ "$status" -eq 0 ]; then
    echo "${PASS} ${description}"
  elif [ "$status" -eq 2 ]; then
    echo "${WARN} ${description}"
  else
    echo "${FAIL} ${description}"
    EXIT_CODE=1
  fi
}

echo "=== PQ-Shield Pre-flight Check ==="
echo

# 1. Virtual environment
if [ -x ".venv/bin/python" ]; then
  check "Virtual environment present (.venv)" 0
else
  check "Virtual environment present (.venv) -- run 'make setup'" 1
fi
PY=".venv/bin/python"
[ -x "$PY" ] || PY="python3"

# 2. liboqs env var + library file
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs) 2>/dev/null
fi
if [ -n "${PQ_SHIELD_OQS_LIB:-}" ] && [ -f "${PQ_SHIELD_OQS_LIB}" ]; then
  check "PQ_SHIELD_OQS_LIB set and file exists (${PQ_SHIELD_OQS_LIB})" 0
elif [ -f "oqs-prefix/lib/liboqs.so" ]; then
  export PQ_SHIELD_OQS_LIB="${REPO_ROOT}/oqs-prefix/lib/liboqs.so"
  check "PQ_SHIELD_OQS_LIB not set, but found default build at oqs-prefix/lib/liboqs.so (using it)" 2
else
  check "liboqs shared library not found -- run 'bash scripts/install_oqs.sh'" 1
fi

# 3. Crypto self-test
if [ "$EXIT_CODE" -eq 0 ] || [ -n "${PQ_SHIELD_OQS_LIB:-}" ]; then
  if PQ_SHIELD_OQS_LIB="${PQ_SHIELD_OQS_LIB:-}" "$PY" -m crypto.oqs_adapter > /tmp/preflight_oqs.log 2>&1; then
    check "ML-KEM-768 / ML-DSA-65 self-test passed" 0
  else
    check "ML-KEM-768 / ML-DSA-65 self-test FAILED -- see /tmp/preflight_oqs.log" 1
  fi
fi

# 4. Model artifact
if [ -f "model/artifacts/model.pkl" ]; then
  check "Trained model artifact present (model/artifacts/model.pkl)" 0
else
  check "Model artifact missing -- run 'python -m model.train'" 1
fi

# 5. pytest suite
if PQ_SHIELD_OQS_LIB="${PQ_SHIELD_OQS_LIB:-}" "$PY" -m pytest -q > /tmp/preflight_pytest.log 2>&1; then
  N_PASSED=$(grep -oE "[0-9]+ passed" /tmp/preflight_pytest.log | tail -1)
  check "pytest suite passing (${N_PASSED:-unknown result})" 0
else
  check "pytest suite FAILED -- see /tmp/preflight_pytest.log" 1
fi

# 6. Streamlit installed
if "$PY" -c "import streamlit, plotly" > /dev/null 2>&1; then
  check "streamlit + plotly importable" 0
else
  check "streamlit/plotly not installed -- run 'pip install -r requirements.txt'" 1
fi

# 7. Demo ports free (8100-8103, 8501)
PORTS_BUSY=""
for port in 8100 8101 8102 8103 8501; do
  if command -v lsof > /dev/null 2>&1 && lsof -i ":${port}" > /dev/null 2>&1; then
    PORTS_BUSY="${PORTS_BUSY} ${port}"
  fi
done
if [ -z "$PORTS_BUSY" ]; then
  check "Demo ports (8100-8103, 8501) free" 0
else
  check "Ports in use:${PORTS_BUSY} -- kill stale processes before the demo (pkill -f uvicorn; pkill -f streamlit)" 2
fi

# 8. Results data present (for the Results Dashboard page)
N_RAW=$(ls results/raw/*.csv 2>/dev/null | wc -l | tr -d ' ')
if [ "$N_RAW" -gt 0 ]; then
  CONFIGS_PRESENT=$("$PY" -c "
import glob, pandas as pd
paths = glob.glob('results/raw/*.csv')
configs = set()
for p in paths:
    try:
        configs.add(pd.read_csv(p)['config'].iloc[0])
    except Exception:
        pass
print(','.join(sorted(configs)))
" 2>/dev/null)
  check "${N_RAW} raw result CSVs found (configs: ${CONFIGS_PRESENT:-unknown})" 0
  case "$CONFIGS_PRESENT" in
    *full_pqc*) : ;;
    *) check "  -> full_pqc NOT in results/raw/ yet -- Results Dashboard chart will be missing that line" 2 ;;
  esac
else
  check "No results/raw/*.csv found -- Results Dashboard page will show 'no data' -- run a sweep first" 2
fi

# 9. HNDL / MITM data present
N_HNDL=$(ls results/hndl/*-summary.json 2>/dev/null | wc -l | tr -d ' ')
N_MITM=$(ls results/mitm/*-summary.json 2>/dev/null | wc -l | tr -d ' ')
if [ "$N_HNDL" -gt 0 ]; then
  check "${N_HNDL} HNDL summary file(s) found" 0
else
  check "No HNDL results yet -- fine, you can run one live in the Threat Scenarios tab (~5-10s)" 2
fi
if [ "$N_MITM" -gt 0 ]; then
  check "${N_MITM} MITM summary file(s) found" 0
else
  check "No MITM results yet -- fine, you can run one live in the Threat Scenarios tab (~5-10s)" 2
fi

echo
if [ "$EXIT_CODE" -eq 0 ]; then
  echo "All required checks passed. Launch with: bash scripts/run_webapp.sh"
else
  echo "One or more required checks FAILED -- fix them before your demo slot."
fi
exit "$EXIT_CODE"
