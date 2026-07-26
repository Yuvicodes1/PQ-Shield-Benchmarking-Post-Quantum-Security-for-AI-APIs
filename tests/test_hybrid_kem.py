import pytest

from crypto.oqs_kem import CIPHERTEXT_BYTES, PUBLIC_KEY_BYTES, SHARED_SECRET_BYTES, MlKem768


def test_ml_kem_768_round_trip():
    kem = MlKem768()
    public_key, secret_key = kem.generate_keypair()
    ciphertext, client_secret = kem.encapsulate(public_key)
    server_secret = kem.decapsulate(ciphertext, secret_key)
    assert len(public_key) == PUBLIC_KEY_BYTES
    assert len(ciphertext) == CIPHERTEXT_BYTES
    assert len(client_secret) == SHARED_SECRET_BYTES
    assert client_secret == server_secret


def test_ml_kem_rejects_wrong_sized_public_key():
    with pytest.raises(ValueError):
        MlKem768().encapsulate(b"invalid")
