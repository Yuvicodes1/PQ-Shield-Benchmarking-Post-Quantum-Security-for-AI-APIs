"""Configuration B: ML-KEM-768 key establishment + ECDSA P-256 signatures."""

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto.config_a_classical import NONCE_BYTES
from crypto.oqs_kem import ALGORITHM, MlKem768


class HybridChannel:
    def __init__(self) -> None:
        self._kem = MlKem768()
        self._kem_public_key, self._kem_secret_key = self._kem.generate_keypair()
        self._signing_private = ec.generate_private_key(ec.SECP256R1())

    def handshake(self) -> tuple[bytes, str]:
        signing_public = self._signing_private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        return self._kem_public_key, signing_public

    def decrypt_request_with_key(self, kem_ciphertext: bytes, envelope: bytes) -> tuple[bytes, bytes]:
        session_key = self._kem.decapsulate(kem_ciphertext, self._kem_secret_key)
        plaintext = AESGCM(session_key).decrypt(envelope[:NONCE_BYTES], envelope[NONCE_BYTES:], None)
        return plaintext, session_key

    def encrypt_and_sign_response(self, plaintext: bytes, session_key: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(NONCE_BYTES)
        envelope = nonce + AESGCM(session_key).encrypt(nonce, plaintext, None)
        signature = self._signing_private.sign(envelope, ec.ECDSA(hashes.SHA256()))
        return envelope, signature

    @property
    def algorithm(self) -> str:
        return f"{ALGORITHM} + ECDSA-P256"
