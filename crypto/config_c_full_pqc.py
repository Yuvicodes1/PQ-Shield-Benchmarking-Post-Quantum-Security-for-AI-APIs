"""Configuration C: ML-KEM-768 key establishment + ML-DSA-65 signatures."""

import os

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:  # pragma: no cover - provide a lightweight fallback for dev environments
    # Minimal fallback to satisfy import resolution in environments without `cryptography`.
    class AESGCM:
        def __init__(self, key: bytes) -> None:
            self._key = key

        def encrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None) -> bytes:
            raise RuntimeError("cryptography AESGCM not available in this environment")

        def decrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None) -> bytes:
            raise RuntimeError("cryptography AESGCM not available in this environment")

from crypto.config_a_classical import NONCE_BYTES
from crypto.oqs_kem import ALGORITHM as KEM_ALGORITHM, MlKem768
from crypto.oqs_sig import ALGORITHM as SIGNATURE_ALGORITHM, MlDsa65


class FullPqcChannel:
    def __init__(self) -> None:
        self._kem = MlKem768()
        self._kem_public_key, self._kem_secret_key = self._kem.generate_keypair()
        self._signature = MlDsa65()
        self._signing_public_key, self._signing_secret_key = self._signature.generate_keypair()

    def handshake(self) -> tuple[bytes, bytes]:
        return self._kem_public_key, self._signing_public_key

    def decrypt_request_with_key(self, kem_ciphertext: bytes, envelope: bytes) -> tuple[bytes, bytes]:
        session_key = self._kem.decapsulate(kem_ciphertext, self._kem_secret_key)
        plaintext = AESGCM(session_key).decrypt(envelope[:NONCE_BYTES], envelope[NONCE_BYTES:], None)
        return plaintext, session_key

    def encrypt_and_sign_response(self, plaintext: bytes, session_key: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(NONCE_BYTES)
        envelope = nonce + AESGCM(session_key).encrypt(nonce, plaintext, None)
        return envelope, self._signature.sign(envelope, self._signing_secret_key)

    @property
    def algorithm(self) -> str:
        return f"{KEM_ALGORITHM} + {SIGNATURE_ALGORITHM}"
