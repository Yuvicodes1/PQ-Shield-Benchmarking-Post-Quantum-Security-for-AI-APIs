"""End-to-end protocol tests for all three crypto configurations.

Each test performs a full handshake -> establish -> accept -> AEAD
encrypt/decrypt -> sign/verify round trip, then confirms that tampering
with either the AEAD ciphertext or the signature is detected.
"""

import pytest

from crypto.aead import AEADError, aead_decrypt, aead_encrypt
from crypto.registry import CONFIG_NAMES, get_client_crypto, get_server_crypto


@pytest.mark.parametrize("config_name", CONFIG_NAMES)
def test_full_roundtrip(config_name):
    server = get_server_crypto(config_name)
    client = get_client_crypto(config_name)

    # 1. Handshake: server generates ephemeral keys, publishes public bundle.
    bundle = server.new_handshake()
    assert bundle.handshake_id

    # 2. Client establishes a session key against the server's public key.
    est = client.establish(bundle.kex_public_key)
    assert len(est.session_key) == 32

    # 3. Server recovers the same session key from the client's kex blob.
    server_session_key, _ = server.accept(bundle.handshake_id, est.kex_blob)
    assert server_session_key == est.session_key

    # 4. Simulate a request payload encrypted client -> server.
    request_plaintext = b'{"features": [0, 1, 2, 3]}'
    req_aead = aead_encrypt(est.session_key, request_plaintext)
    recovered_request = aead_decrypt(server_session_key, req_aead.nonce, req_aead.ciphertext)
    assert recovered_request == request_plaintext

    # 5. Simulate a response payload encrypted server -> client, then signed.
    response_plaintext = b'{"prediction": 7, "probabilities": [0.01, 0.02]}'
    resp_aead = aead_encrypt(server_session_key, response_plaintext)
    envelope = resp_aead.nonce + resp_aead.ciphertext
    signature, _ = server.sign(bundle.handshake_id, envelope)

    valid, _ = client.verify(envelope, signature, bundle.sig_public_key)
    assert valid is True

    recovered_response = aead_decrypt(est.session_key, resp_aead.nonce, resp_aead.ciphertext)
    assert recovered_response == response_plaintext

    server.forget(bundle.handshake_id)


@pytest.mark.parametrize("config_name", CONFIG_NAMES)
def test_tampered_ciphertext_rejected(config_name):
    server = get_server_crypto(config_name)
    client = get_client_crypto(config_name)

    bundle = server.new_handshake()
    est = client.establish(bundle.kex_public_key)
    server_session_key, _ = server.accept(bundle.handshake_id, est.kex_blob)

    plaintext = b'{"prediction": 3}'
    aead = aead_encrypt(server_session_key, plaintext)

    tampered_ciphertext = bytearray(aead.ciphertext)
    tampered_ciphertext[0] ^= 0xFF  # flip a bit inside the ciphertext body

    with pytest.raises(AEADError):
        aead_decrypt(est.session_key, aead.nonce, bytes(tampered_ciphertext))


@pytest.mark.parametrize("config_name", CONFIG_NAMES)
def test_tampered_signature_rejected(config_name):
    server = get_server_crypto(config_name)
    client = get_client_crypto(config_name)

    bundle = server.new_handshake()
    message = b"response-envelope-bytes"
    signature, _ = server.sign(bundle.handshake_id, message)

    tampered_signature = bytearray(signature)
    tampered_signature[-1] ^= 0xFF

    valid, _ = client.verify(message, bytes(tampered_signature), bundle.sig_public_key)
    assert valid is False


@pytest.mark.parametrize("config_name", CONFIG_NAMES)
def test_tampered_message_rejected(config_name):
    """A byte-for-byte correct signature over a *different* message must fail verification."""
    server = get_server_crypto(config_name)
    client = get_client_crypto(config_name)

    bundle = server.new_handshake()
    message = b"the-real-response-bytes"
    signature, _ = server.sign(bundle.handshake_id, message)

    valid, _ = client.verify(b"a-substituted-response-bytes!!!", signature, bundle.sig_public_key)
    assert valid is False


def test_wrong_session_key_fails_to_decrypt():
    """Sanity check that AEAD is actually keyed -- not a crypto-config test per se."""
    key_a = b"\x01" * 32
    key_b = b"\x02" * 32
    aead = aead_encrypt(key_a, b"secret payload")
    with pytest.raises(AEADError):
        aead_decrypt(key_b, aead.nonce, aead.ciphertext)
