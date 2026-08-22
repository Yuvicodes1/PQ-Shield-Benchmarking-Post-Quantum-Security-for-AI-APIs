"""CLI client for Configuration B -- Hybrid (ML-KEM-768 + ECDSA P-256).

Run with: python -m api.client_hybrid --url http://127.0.0.1:8000 --features ...
"""

from api._client_cli import main

if __name__ == "__main__":
    main("hybrid")
