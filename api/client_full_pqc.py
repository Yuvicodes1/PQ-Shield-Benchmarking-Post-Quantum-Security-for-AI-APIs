"""Reusable Configuration C client for ML-KEM-768 + ML-DSA-65."""

import argparse
import json
from dataclasses import dataclass

import httpx

from crypto.config_a_classical import b64, pack_envelope, unb64, unpack_envelope
from crypto.oqs_kem import MlKem768
from crypto.oqs_sig import MlDsa65


@dataclass
class FullPqcClient:
    base_url: str

    def predict(self, features: list[float]) -> dict:
        with httpx.Client(base_url=self.base_url, timeout=20.0) as client:
            handshake = client.get("/secure/handshake").raise_for_status().json()
            kem_ciphertext, session_key = MlKem768().encapsulate(unb64(handshake["kem_public_key"]))
            signing_key = unb64(handshake["signing_public_key"])
            envelope = pack_envelope(session_key, json.dumps({"input": features}).encode())
            response = client.post("/secure/predict", json={
                "kem_ciphertext": b64(kem_ciphertext), "envelope": b64(envelope)
            }).raise_for_status().json()
            encrypted_response = unb64(response["envelope"])
            if not MlDsa65().verify(encrypted_response, unb64(response["signature"]), signing_key):
                raise ValueError("Server response signature verification failed")
            result = json.loads(unpack_envelope(session_key, encrypted_response))
            result["crypto_ms"] = response["crypto_ms"]
            return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--features", required=True)
    args = parser.parse_args()
    print(json.dumps(FullPqcClient(args.url).predict([float(x) for x in args.features.split(",")]), indent=2))
