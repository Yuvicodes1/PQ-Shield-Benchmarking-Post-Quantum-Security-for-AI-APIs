"""CLI client for Configuration A -- Classical (RSA-2048-OAEP + ECDSA P-256).

Run with: python -m api.client --url http://127.0.0.1:8000 --features ...
"""

from api._client_cli import main

if __name__ == "__main__":
    main("classical")
