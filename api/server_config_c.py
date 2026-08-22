"""Configuration C -- Full PQC (ML-KEM-768 + ML-DSA-65).

Run with: uvicorn api.server_config_c:app --port 8000
"""

from api.secure_app import build_app

app = build_app("full_pqc")
