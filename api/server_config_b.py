"""Configuration B -- Hybrid (ML-KEM-768 + ECDSA P-256).

Run with: uvicorn api.server_config_b:app --port 8000
"""

from api.secure_app import build_app

app = build_app("hybrid")
