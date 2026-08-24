import json
import os

import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

from api.server import app as control_app
from api.server_config_a import app as protected_app
from crypto.config_a_classical import ClassicalChannel, b64, pack_envelope, unb64, unpack_envelope

FEATURES = [0.0] * 64


def test_classical_channel_rejects_tampered_ciphertext():
    channel = ClassicalChannel()
    with pytest.raises(Exception):
        channel.decrypt_request(b"not-a-real-rsa-ciphertext", b"also-invalid")


def test_control_server_exposes_secure_endpoints():
    client = TestClient(control_app)
    handshake = client.get("/secure/handshake")
    assert handshake.status_code == 404


def test_protected_round_trip_returns_prediction():
    client = TestClient(protected_app)
    handshake = client.get("/secure/handshake").json()
    rsa_key = serialization.load_pem_public_key(handshake["kex_public_key"].encode())
    signing_key = serialization.load_pem_public_key(handshake["sig_public_key"].encode())
    session_key = os.urandom(32)
    encrypted_key = rsa_key.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    envelope = pack_envelope(session_key, json.dumps({"input": FEATURES}).encode())
    response = client.post(
        "/secure/predict",
        json={"encrypted_key": b64(encrypted_key), "envelope": b64(envelope)},
    )
    assert response.status_code == 200
    payload = response.json()
    encrypted_response = unb64(payload["envelope"])
    signing_key.verify(unb64(payload["signature"]), encrypted_response, ec.ECDSA(hashes.SHA256()))
    result = json.loads(unpack_envelope(session_key, encrypted_response))
    assert 0 <= result["prediction"] <= 9
    assert len(result["probabilities"]) == 10
    assert result["inference_ms"] >= 0
