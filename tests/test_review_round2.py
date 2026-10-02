"""Tests for the second review round: the Hybrid-KEX-PQ configuration,
authenticated handshakes (transcript signature under a pinned identity key),
the client's enforcement of the requested checkpoint schedule, and the
CPU-time fields on sign/verify metadata."""

import base64

import pytest
from fastapi.testclient import TestClient

from api.secure_app import build_app
from crypto.handshake_auth import IdentityKey, transcript, verify_handshake
from crypto.registry import get_client_crypto, get_server_crypto
from crypto.streaming import HashChainClientState, get_server_strategy, verify_hash_chain_chunk

b64d = lambda s: base64.b64decode(s.encode())
b64e = lambda b: base64.b64encode(b).decode()


def test_hybrid_kex_pq_sizes_and_agreement():
    server, client = get_server_crypto("hybrid_kex_pq"), get_client_crypto("hybrid_kex_pq")
    bundle = server.new_handshake()
    est = client.establish(bundle.kex_public_key)
    key, _ = server.accept(bundle.handshake_id, est.kex_blob)
    assert key == est.session_key
    assert (len(bundle.kex_public_key), len(est.kex_blob), len(bundle.sig_public_key)) == (1216, 1120, 1952)
    sig, meta = server.sign(bundle.handshake_id, b"m")
    assert len(sig) == 3309 and meta["sign_cpu_ms"] >= 0
    ok, vmeta = client.verify(b"m", sig, bundle.sig_public_key)
    assert ok and "verify_cpu_ms" in vmeta


@pytest.mark.parametrize("config_name", ["classical_ecdhe", "full_pqc", "hybrid_kex_pq"])
def test_authenticated_handshake_accepts_genuine_rejects_substituted(config_name, monkeypatch):
    monkeypatch.setenv("PQ_SHIELD_AUTH_HANDSHAKE", "1")
    with TestClient(build_app(config_name)) as tc:
        ident = tc.get("/secure/identity").json()
        pinned = {"algorithm": ident["algorithm"], "public_key": b64d(ident["public_key"])}
        hs = tc.get("/secure/handshake").json()
        assert verify_handshake(hs, pinned, b64d)[0]

        # attacker substitutes its own key shares, keeping the server's signature
        atk = get_server_crypto(config_name).new_handshake(hs["handshake_id"])
        forged = dict(hs, kex_public_key=b64e(atk.kex_public_key), sig_public_key=b64e(atk.sig_public_key))
        assert not verify_handshake(forged, pinned, b64d)[0]

        # ... or re-signs the transcript with its own identity key
        own = IdentityKey.generate(pinned["algorithm"])
        sig, _ = own.sign(transcript(hs["handshake_id"], hs["kex_algorithm"], hs["sig_algorithm"],
                                     atk.kex_public_key, atk.sig_public_key))
        assert not verify_handshake(dict(forged, transcript_signature=b64e(sig)), pinned, b64d)[0]


def test_unauthenticated_server_has_no_identity(monkeypatch):
    monkeypatch.delenv("PQ_SHIELD_AUTH_HANDSHAKE", raising=False)
    with TestClient(build_app("hybrid")) as tc:
        assert tc.get("/secure/identity").status_code == 404
        hs = tc.get("/secure/handshake").json()
        assert hs.get("transcript_signature") is None
        pinned = {"algorithm": "ECDSA-P256-SHA256", "public_key": b"x"}
        assert not verify_handshake(hs, pinned, b64d)[0]  # a missing signature never passes


@pytest.mark.parametrize("k", [2, 3])
def test_client_rejects_stripped_checkpoint(k):
    server, client = get_server_crypto("hybrid"), get_client_crypto("hybrid")
    bundle = server.new_handshake()
    est = client.establish(bundle.kex_public_key)
    key, _ = server.accept(bundle.handshake_id, est.kex_blob)
    strategy = get_server_strategy("hash_chain", server, bundle.handshake_id, key, checkpoint_interval=k)
    rows = [strategy.add_chunk(f"c{i}".encode(), i) for i in range(2 * k)]
    assert rows[k - 1]["signature"] is not None
    rows[k - 1] = dict(rows[k - 1], signature=None)  # attacker strips the first checkpoint

    enforcing = HashChainClientState(bundle.handshake_id, checkpoint_interval=k)
    legacy = HashChainClientState(bundle.handshake_id)  # v2 client: no schedule check
    for i, row in enumerate(rows[:k]):
        r_new = verify_hash_chain_chunk(row, enforcing, key, bundle.sig_public_key, client)
        r_old = verify_hash_chain_chunk(row, legacy, key, bundle.sig_public_key, client)
        assert r_new["checkpoint_missing"] == (i == k - 1)
        assert not r_old["checkpoint_missing"]


def test_genuine_checkpointed_stream_never_flags_missing():
    server, client = get_server_crypto("full_pqc"), get_client_crypto("full_pqc")
    bundle = server.new_handshake()
    est = client.establish(bundle.kex_public_key)
    key, _ = server.accept(bundle.handshake_id, est.kex_blob)
    strategy = get_server_strategy("hash_chain", server, bundle.handshake_id, key, checkpoint_interval=4)
    state = HashChainClientState(bundle.handshake_id, checkpoint_interval=4)
    for i in range(11):
        r = verify_hash_chain_chunk(strategy.add_chunk(b"t", i), state, key, bundle.sig_public_key, client)
        assert not r["checkpoint_missing"]
        assert r["checkpoint_valid"] in (None, True)
