"""Configuration A -- Classical Baseline.

Key establishment: RSA-2048-OAEP key transport (client generates the AES
session key locally and encrypts it to the server's RSA public key -- the
realistic classical analogue to a KEM, matching current production TLS/API
practice when ECDHE is not used).

Signatures: ECDSA P-256 over the response AEAD envelope.

This is the reference implementation everything else in the benchmark is
measured against (design doc Phase 2 note: bugs here invalidate every later
number), so it intentionally does the least amount of "cleverness" possible.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization

from .aead import derive_session_key
from .base import ClientCryptoConfig, EstablishResult, HandshakeBundle, ServerCryptoConfig
from .instrumentation import Timer

RSA_KEY_SIZE_BITS = 2048
_OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
)


def _rsa_public_der(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _ec_public_der(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@dataclass
class _HandshakeState:
    rsa_private: rsa.RSAPrivateKey
    ec_private: ec.EllipticCurvePrivateKey


class ClassicalServerCrypto(ServerCryptoConfig):
    name = "classical"
    kex_algorithm = "RSA-2048-OAEP"
    sig_algorithm = "ECDSA-P256-SHA256"

    def __init__(self) -> None:
        self._sessions: dict[str, _HandshakeState] = {}

    def new_handshake(self, handshake_id: str | None = None) -> HandshakeBundle:
        handshake_id = handshake_id or str(uuid.uuid4())
        with Timer() as t:
            rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE_BITS)
            ec_private = ec.generate_private_key(ec.SECP256R1())
        self._sessions[handshake_id] = _HandshakeState(rsa_private, ec_private)

        rsa_pub_der = _rsa_public_der(rsa_private.public_key())
        ec_pub_der = _ec_public_der(ec_private.public_key())
        return HandshakeBundle(
            handshake_id=handshake_id,
            kex_public_key=rsa_pub_der,
            sig_public_key=ec_pub_der,
            meta={
                "gen_ms": t.elapsed_ms,
                "kex_public_key_bytes": len(rsa_pub_der),
                "sig_public_key_bytes": len(ec_pub_der),
                "kex_algorithm": self.kex_algorithm,
                "sig_algorithm": self.sig_algorithm,
            },
        )

    def accept(self, handshake_id: str, kex_blob: bytes) -> tuple[bytes, dict]:
        state = self._sessions[handshake_id]
        with Timer() as t:
            raw_secret = state.rsa_private.decrypt(kex_blob, _OAEP_PADDING)
            session_key = derive_session_key(raw_secret, context=b"pq-shield-classical")
        return session_key, {"decapsulate_ms": t.elapsed_ms, "kex_blob_bytes": len(kex_blob)}

    def sign(self, handshake_id: str, message: bytes) -> tuple[bytes, dict]:
        state = self._sessions[handshake_id]
        with Timer() as t:
            signature = state.ec_private.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature, {"sign_ms": t.elapsed_ms, "signature_bytes": len(signature)}

    def forget(self, handshake_id: str) -> None:
        self._sessions.pop(handshake_id, None)


class ClassicalClientCrypto(ClientCryptoConfig):
    name = "classical"

    def establish(self, kex_public_key: bytes) -> EstablishResult:
        import os

        rsa_pub = serialization.load_der_public_key(kex_public_key)
        raw_secret = os.urandom(32)
        session_key = derive_session_key(raw_secret, context=b"pq-shield-classical")
        with Timer() as t:
            kex_blob = rsa_pub.encrypt(raw_secret, _OAEP_PADDING)
        return EstablishResult(
            session_key=session_key,
            kex_blob=kex_blob,
            meta={"handshake_encrypt_ms": t.elapsed_ms, "kex_blob_bytes": len(kex_blob)},
        )

    def verify(self, message: bytes, signature: bytes, sig_public_key: bytes) -> tuple[bool, dict]:
        pub = serialization.load_der_public_key(sig_public_key)
        with Timer() as t:
            try:
                pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
                ok = True
            except Exception:
                ok = False
        return ok, {"verify_ms": t.elapsed_ms}
