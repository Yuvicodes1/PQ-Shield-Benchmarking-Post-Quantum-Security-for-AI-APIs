"""Configuration C' -- Hybrid-KEX-PQ (X25519MLKEM768 + ML-DSA-65).

Run with: uvicorn api.server_config_hybridkexpq:app --port 8000
"""

from api.secure_app import build_app

app = build_app("hybrid_kex_pq")
