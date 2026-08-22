"""Configuration A: RSA-2048/OAEP + AES-256-GCM + ECDSA P-256.

RSA transports a fresh symmetric key for each request. AES-GCM protects JSON
payloads; the server then signs the encrypted response envelope with ECDSA.
"""

import os
from base64 import b64decode, b64encode

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto.channel import CryptoChannel, HandshakeMaterial

NONCE_BYTES = 12


class ClassicalChannel(CryptoChannel):
    def __init__(self) -> None:
        self._rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._signing_private = ec.generate_private_key(ec.SECP256R1())

    def handshake(self) -> HandshakeMaterial:
        rsa_public = self._rsa_private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        signing_public = self._signing_private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return HandshakeMaterial(rsa_public, signing_public, "RSA-2048/OAEP + ECDSA-P256")

    def decrypt_request(self, encrypted_key: bytes, envelope: bytes) -> bytes:
        session_key = self._rsa_private.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        if len(session_key) != 32:
            raise ValueError("Invalid AES-256 session key")
        return AESGCM(session_key).decrypt(envelope[:NONCE_BYTES], envelope[NONCE_BYTES:], None)

    def encrypt_and_sign_response(self, plaintext: bytes, session_key: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(NONCE_BYTES)
        envelope = nonce + AESGCM(session_key).encrypt(nonce, plaintext, None)
        signature = self._signing_private.sign(envelope, ec.ECDSA(hashes.SHA256()))
        return envelope, signature

    def decrypt_request_with_key(self, encrypted_key: bytes, envelope: bytes) -> tuple[bytes, bytes]:
        """Internal server helper retaining the key for the response envelope."""
        session_key = self._rsa_private.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        plaintext = AESGCM(session_key).decrypt(envelope[:NONCE_BYTES], envelope[NONCE_BYTES:], None)
        return plaintext, session_key


def pack_envelope(session_key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_BYTES)
    return nonce + AESGCM(session_key).encrypt(nonce, plaintext, None)


def unpack_envelope(session_key: bytes, envelope: bytes) -> bytes:
    return AESGCM(session_key).decrypt(envelope[:NONCE_BYTES], envelope[NONCE_BYTES:], None)


def b64(data: bytes) -> str:
    return b64encode(data).decode("ascii")


def unb64(data: str) -> bytes:
    return b64decode(data.encode("ascii"), validate=True)
