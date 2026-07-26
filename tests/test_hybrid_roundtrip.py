import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from api.server_config_b import app
from crypto.config_a_classical import b64, pack_envelope, unb64, unpack_envelope
from crypto.oqs_kem import MlKem768


def test_hybrid_api_round_trip():
    with TestClient(app) as client:
        handshake = client.get("/secure/handshake").json()
        kem_ciphertext, session_key = MlKem768().encapsulate(unb64(handshake["kem_public_key"]))
        signing_key = serialization.load_pem_public_key(handshake["signing_public_key"].encode())
        envelope = pack_envelope(session_key, json.dumps({"input": [0.0] * 64}).encode())
        response = client.post("/secure/predict", json={
            "kem_ciphertext": b64(kem_ciphertext), "envelope": b64(envelope)
        })
    assert response.status_code == 200
    payload = response.json()
    encrypted_response = unb64(payload["envelope"])
    signing_key.verify(unb64(payload["signature"]), encrypted_response, ec.ECDSA(hashes.SHA256()))
    result = json.loads(unpack_envelope(session_key, encrypted_response))
    assert 0 <= result["prediction"] <= 9
    assert len(result["probabilities"]) == 10
