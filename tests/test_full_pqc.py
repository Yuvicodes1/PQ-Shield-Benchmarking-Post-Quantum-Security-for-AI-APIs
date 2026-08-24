import json

from fastapi.testclient import TestClient

from api.server_config_c import app
from crypto.config_a_classical import b64, pack_envelope, unb64, unpack_envelope
from crypto.oqs_kem import MlKem768
from crypto.oqs_sig import PUBLIC_KEY_BYTES, SIGNATURE_BYTES, MlDsa65


def test_ml_dsa_65_round_trip_and_tamper_detection():
    signature_scheme = MlDsa65()
    public_key, secret_key = signature_scheme.generate_keypair()
    message = b"protected response"
    signature = signature_scheme.sign(message, secret_key)
    assert len(public_key) == PUBLIC_KEY_BYTES
    assert len(signature) <= SIGNATURE_BYTES
    assert signature_scheme.verify(message, signature, public_key)
    assert not signature_scheme.verify(message + b"!", signature, public_key)


def test_full_pqc_api_round_trip():
    with TestClient(app) as client:
        handshake = client.get("/secure/handshake").json()
        kem_ciphertext, session_key = MlKem768().encapsulate(unb64(handshake["kex_public_key"]))
        signing_key = unb64(handshake["sig_public_key"])
        envelope = pack_envelope(session_key, json.dumps({"input": [0.0] * 64}).encode())
        response = client.post("/secure/predict", json={
            "kem_ciphertext": b64(kem_ciphertext), "envelope": b64(envelope)
        })
    assert response.status_code == 200
    payload = response.json()
    encrypted_response = unb64(payload["envelope"])
    assert MlDsa65().verify(encrypted_response, unb64(payload["signature"]), signing_key)
    result = json.loads(unpack_envelope(session_key, encrypted_response))
    assert 0 <= result["prediction"] <= 9
    assert len(result["probabilities"]) == 10
