"""Bootstrap helper for every Streamlit page: makes sure the repo root is on
sys.path and PQ_SHIELD_OQS_LIB is set from .env *before* anything imports
crypto.oqs_adapter (which loads the liboqs shared library at import time via
ctypes.CDLL -- an import-order mistake here fails with an unhelpful
"library not found" error instead of a clear one).

Every page under pages/*.py and app.py itself must call
`load_dotenv_if_needed()` as its first import-time action, before importing
anything from webapp.*, crypto.*, api.*, analysis.*, bench.*, or threats.*.
"""

from __future__ import annotations

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _ensure_repo_root_on_path() -> None:
    if REPO_ROOT not in sys.path:
        sys.path.insert(0, REPO_ROOT)


def load_dotenv_if_needed() -> None:
    _ensure_repo_root_on_path()
    env_path = os.path.join(REPO_ROOT, ".env")
    if not os.path.isfile(env_path):
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip())
