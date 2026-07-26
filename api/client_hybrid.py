"""Reusable Configuration B client; suitable for future benchmark integration."""

import argparse
import json
from dataclasses import dataclass

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from crypto.config_a_classical import b64, pack_envelope, unb64, unpack_envelope
from crypto.oqs_kem import MlKem768


@dataclass
class HybridClient:
    base_url: str

    def predict(self, features: list[float]) -> dict:
        with httpx.Client(base_url=self.base_url, timeout=20.0) as client:
            handshake = client.get("/secure/handshake").raise_for_status().json()
            kem = MlKem768()
            kem_ciphertext, session_key = kem.encapsulate(unb64(handshake["kem_public_key"]))
            signing_key = serialization.load_pem_public_key(handshake["signing_public_key"].encode())
            envelope = pack_envelope(session_key, json.dumps({"input": features}).encode())
            response = client.post("/secure/predict", json={
                "kem_ciphertext": b64(kem_ciphertext), "envelope": b64(envelope)
            }).raise_for_status().json()
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
    parser.add_argument("--features", required=True)
    args = parser.parse_args()
    print(json.dumps(HybridClient(args.url).predict([float(x) for x in args.features.split(",")]), indent=2))
