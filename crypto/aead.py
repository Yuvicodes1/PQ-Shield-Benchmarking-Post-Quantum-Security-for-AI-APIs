"""AES-256-GCM helpers shared by all three protected configurations.

Every configuration (Classical, Hybrid, Full PQC) uses the *same* symmetric
payload encryption -- AES-256-GCM keyed by a per-request session key derived
from that configuration's key-establishment step (RSA-OAEP key transport for
Classical, ML-KEM-768 encapsulation for Hybrid/Full PQC). This isolates the
project's independent variable to the asymmetric key-establishment and
signature primitives, which is what PQ-Shield is actually benchmarking.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

AES_KEY_BYTES = 32  # AES-256
GCM_NONCE_BYTES = 12


class AEADError(RuntimeError):
    """Raised on authenticated-decryption failure (tamper detected)."""


@dataclass
class AEADResult:
    nonce: bytes
    ciphertext: bytes  # includes the GCM authentication tag


def derive_session_key(shared_secret: bytes, context: bytes = b"pq-shield-session-key") -> bytes:
    """HKDF-SHA256 the raw KEM/RSA shared secret into a uniform AES-256 key.

    Applied uniformly across Classical/Hybrid/Full PQC so that "the key was
    32 raw KEM bytes" is never a confound between configurations -- even
    though ML-KEM-768's shared secret is already 32 bytes, we still run it
    through HKDF for domain separation and to match standard practice.
    """
    hkdf = HKDF(algorithm=hashes.SHA256(), length=AES_KEY_BYTES, salt=None, info=context)
    return hkdf.derive(shared_secret)


def aead_encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> AEADResult:
    nonce = os.urandom(GCM_NONCE_BYTES)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return AEADResult(nonce=nonce, ciphertext=ciphertext)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes | None = None) -> bytes:
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except Exception as exc:  # cryptography raises InvalidTag
        raise AEADError("AES-GCM authentication failed (payload tampered or wrong key)") from exc
