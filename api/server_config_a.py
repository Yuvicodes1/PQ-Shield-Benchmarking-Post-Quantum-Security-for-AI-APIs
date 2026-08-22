"""Configuration A -- Classical (RSA-2048-OAEP + ECDSA P-256).

Run with: uvicorn api.server_config_a:app --port 8000
"""

from api.secure_app import build_app

app = build_app("classical")
