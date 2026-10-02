"""Configuration B' -- Hybrid-KEX (X25519MLKEM768 + ECDSA P-256).

Run with: uvicorn api.server_config_hybridkex:app --port 8000
"""

from api.secure_app import build_app

app = build_app("hybrid_kex")
