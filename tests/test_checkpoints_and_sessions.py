"""Tests for checkpointed hash-chain verification, session resumption, and the
X25519MLKEM768 hybrid key exchange.

Checkpoints: the server signs the running chain hash every k chunks; the
client must verify each checkpoint against its OWN chain, so a dropped or
reordered chunk is caught at the next checkpoint, mid-stream.

Sessions: with keep_session=True the server caches the session key, later
requests carry no kex blob, and the final request (keep_session=False)
makes the server forget the session.
"""

import base64
import json

import pytest
from fastapi.testclient import TestClient

from api.secure_app import build_app
from crypto.aead import aead_decrypt, aead_encrypt
from crypto.registry import CONFIG_NAMES, get_client_crypto, get_server_crypto
from crypto.streaming import HashChainClientState, get_server_strategy, verify_hash_chain_chunk

CHUNKS = [f"chunk-{i} ".encode() for i in range(8)]


def _handshake(config_name: str):
    server = get_server_crypto(config_name)
    client = get_client_crypto(config_name)
    bundle = server.new_handshake()
    est = client.establish(bundle.kex_public_key)
    session_key, _ = server.accept(bundle.handshake_id, est.kex_blob)
    assert session_key == est.session_key
    return server, client, bundle, session_key


def _stream(config_name: str, k: int):
    server, client, bundle, session_key = _handshake(config_name)
    strategy = get_server_strategy("hash_chain", server, bundle.handshake_id, session_key, checkpoint_interval=k)
    rows = [strategy.add_chunk(c, i) for i, c in enumerate(CHUNKS)]
    return client, bundle, session_key, rows


def _verify(rows, client, bundle, session_key):
    state = HashChainClientState()
    return [verify_hash_chain_chunk(r, state, session_key, bundle.sig_public_key, client) for r in rows]


@pytest.mark.parametrize("config_name", CONFIG_NAMES)
@pytest.mark.parametrize("k", [1, 2, 3])
def test_checkpoints_verify_on_untampered_stream(config_name, k):
    client, bundle, session_key, rows = _stream(config_name, k)
    results = _verify(rows, client, bundle, session_key)
    checkpoints = [r for r in results if r["checkpoint"]]
    assert len(checkpoints) == len(CHUNKS) // k
    assert all(r["checkpoint_valid"] for r in checkpoints)


@pytest.mark.parametrize("config_name", ["hybrid", "full_pqc"])
def test_checkpoint_catches_dropped_chunk_mid_stream(config_name):
    client, bundle, session_key, rows = _stream(config_name, 2)
    tampered = rows[:3] + rows[4:]  # drop chunk 3
    results = _verify(tampered, client, bundle, session_key)
    first_bad = next(i for i, r in enumerate(results) if r["checkpoint"] and not r["checkpoint_valid"])
    assert first_bad < len(tampered) - 1  # detected before the stream ends


@pytest.mark.parametrize("config_name", ["hybrid", "full_pqc"])
def test_checkpoint_catches_reorder_mid_stream(config_name):
    client, bundle, session_key, rows = _stream(config_name, 2)
    tampered = list(rows)
    tampered[2], tampered[3] = tampered[3], tampered[2]
    results = _verify(tampered, client, bundle, session_key)
    assert any(r["checkpoint"] and not r["checkpoint_valid"] for r in results[:5])


def test_hybrid_kex_sizes_and_agreement():
    server = get_server_crypto("hybrid_kex")
    client = get_client_crypto("hybrid_kex")
    bundle = server.new_handshake()
    assert len(bundle.kex_public_key) == 1184 + 32  # ML-KEM-768 encapsulation key || X25519
    est = client.establish(bundle.kex_public_key)
    assert len(est.kex_blob) == 1088 + 32  # ML-KEM-768 ciphertext || X25519
    session_key, _ = server.accept(bundle.handshake_id, est.kex_blob)
    assert session_key == est.session_key


def test_hybrid_kex_rejects_tampered_x25519_half():
    server = get_server_crypto("hybrid_kex")
    client = get_client_crypto("hybrid_kex")
    bundle = server.new_handshake()
    est = client.establish(bundle.kex_public_key)
    blob = bytearray(est.kex_blob)
    blob[-1] ^= 0x01  # flip a bit in the X25519 share only
    session_key, _ = server.accept(bundle.handshake_id, bytes(blob))
    assert session_key != est.session_key  # both halves feed the key


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


@pytest.mark.parametrize("config_name", ["classical_ecdhe", "hybrid", "hybrid_kex"])
def test_session_resumption_reuses_key_then_forgets(config_name):
    app = TestClient(build_app(config_name))
    client = get_client_crypto(config_name)
    hs = app.get("/secure/handshake").json()
    est = client.establish(base64.b64decode(hs["kex_public_key"]))
    body = {"input": [0.0] * 64}

    def call(kex_blob: bytes, keep: bool):
        req = aead_encrypt(est.session_key, json.dumps(body).encode())
        return app.post("/secure/predict", json={
            "handshake_id": hs["handshake_id"], "kex_blob": _b64(kex_blob), "keep_session": keep,
            "nonce": _b64(req.nonce), "ciphertext": _b64(req.ciphertext),
        })

    first = call(est.kex_blob, True)
    assert first.status_code == 200, first.text
    for keep in (True, False):  # resumed requests: no kex blob
        r = call(b"", keep)
        assert r.status_code == 200, r.text
        j = r.json()
        aead_decrypt(est.session_key, base64.b64decode(j["nonce"]), base64.b64decode(j["ciphertext"]))
        assert j["server_timing_ms"]["decapsulate_ms"] == 0.0
    assert call(b"", True).status_code == 404  # session ended with keep_session=False


def test_default_requests_unchanged_without_keep_session():
    app = TestClient(build_app("hybrid"))
    client = get_client_crypto("hybrid")
    hs = app.get("/secure/handshake").json()
    est = client.establish(base64.b64decode(hs["kex_public_key"]))
    req = aead_encrypt(est.session_key, json.dumps({"input": [0.0] * 64}).encode())
    payload = {"handshake_id": hs["handshake_id"], "kex_blob": _b64(est.kex_blob),
               "nonce": _b64(req.nonce), "ciphertext": _b64(req.ciphertext)}
    assert app.post("/secure/predict", json=payload).status_code == 200
    assert app.post("/secure/predict", json=payload).status_code == 404  # forgotten, as before
