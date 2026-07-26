"""Reusable Configuration A client; used later by the benchmark runner."""

import argparse
import json
import os
from dataclasses import dataclass
from typing import Optional

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

from crypto.config_a_classical import b64, pack_envelope, unb64, unpack_envelope


@dataclass
class ClassicalClient:
    base_url: str
    transport: Optional[httpx.BaseTransport] = None

    def predict(self, features: list[float]) -> dict:
        with httpx.Client(base_url=self.base_url, transport=self.transport, timeout=20.0) as client:
            handshake = client.get("/secure/handshake").raise_for_status().json()
            rsa_key = serialization.load_pem_public_key(handshake["key_exchange_public_key"].encode())
            signing_key = serialization.load_pem_public_key(handshake["signing_public_key"].encode())
            session_key = os.urandom(32)
            encrypted_key = rsa_key.encrypt(
                session_key,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
            )
            envelope = pack_envelope(session_key, json.dumps({"input": features}).encode())
            response = client.post(
                "/secure/predict",
                json={"encrypted_key": b64(encrypted_key), "envelope": b64(envelope)},
            ).raise_for_status().json()
            encrypted_response = unb64(response["envelope"])
            try:
                signing_key.verify(unb64(response["signature"]), encrypted_response, ec.ECDSA(hashes.SHA256()))
            except InvalidSignature as exc:
                raise ValueError("Server response signature verification failed") from exc
            result = json.loads(unpack_envelope(session_key, encrypted_response))
            result["crypto_ms"] = response["crypto_ms"]
            return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--features", required=True, help="Comma-separated 64 values")
    args = parser.parse_args()
    values = [float(value) for value in args.features.split(",")]
    print(json.dumps(ClassicalClient(args.url).predict(values), indent=2))
