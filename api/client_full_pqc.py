"""CLI client for Configuration C -- Full PQC (ML-KEM-768 + ML-DSA-65).

Run with: python -m api.client_full_pqc --url http://127.0.0.1:8000 --features ...
"""

from api._client_cli import main

if __name__ == "__main__":
    main("full_pqc")
