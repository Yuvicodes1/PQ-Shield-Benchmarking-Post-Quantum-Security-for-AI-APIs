"""Configuration A' -- Classical-ECDHE (the production classical baseline).

Key establishment: ephemeral-ephemeral X25519 Diffie-Hellman. The server
generates a fresh X25519 key pair per handshake (as a TLS 1.3 server does for
its key_share); the client generates its own, computes the shared secret, and
sends its 32-byte public key as the kex blob. This is what "classical" means
in deployed TLS 1.3 today -- RSA key transport (Configuration A) was removed
from TLS 1.3 entirely -- and it is the classical half of the X25519MLKEM768
hybrid group that browsers and CDNs now negotiate.

Signatures: ECDSA P-256 over the response AEAD envelope -- byte-for-byte the
same signature side as Configuration B (Hybrid). So:
  * A' vs. B isolates exactly one variable: X25519 vs. ML-KEM-768 key
    establishment (the migration operators actually face);
  * A' vs. A isolates ECDHE vs. per-handshake RSA-2048 key transport.

Quantum status: X25519 falls to Shor's algorithm just as RSA does, so a
harvested handshake is decryptable by a future CRQC -- same HNDL exposure as
Configuration A, at a tiny fraction of its handshake cost.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .aead import derive_session_key
from .base import ClientCryptoConfig, EstablishResult, HandshakeBundle, ServerCryptoConfig
from .instrumentation import Timer

X25519_PUBLIC_KEY_BYTES = 32
_HKDF_CONTEXT = b"pq-shield-classical-ecdhe"


def _ec_public_der(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _x25519_raw(pub: X25519PublicKey) -> bytes:
    raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    assert len(raw) == X25519_PUBLIC_KEY_BYTES
    return raw


@dataclass
class _HandshakeState:
    x25519_private: X25519PrivateKey
    ec_private: ec.EllipticCurvePrivateKey


class ClassicalECDHEServerCrypto(ServerCryptoConfig):
    name = "classical_ecdhe"
    kex_algorithm = "X25519"
    sig_algorithm = "ECDSA-P256-SHA256"

    def __init__(self) -> None:
        self._sessions: dict[str, _HandshakeState] = {}

    def new_handshake(self, handshake_id: str | None = None) -> HandshakeBundle:
        handshake_id = handshake_id or str(uuid.uuid4())
        with Timer() as t:
            x_private = X25519PrivateKey.generate()
            ec_private = ec.generate_private_key(ec.SECP256R1())
        self._sessions[handshake_id] = _HandshakeState(x_private, ec_private)

        x_pub = _x25519_raw(x_private.public_key())
        ec_pub_der = _ec_public_der(ec_private.public_key())
        return HandshakeBundle(
            handshake_id=handshake_id,
            kex_public_key=x_pub,
            sig_public_key=ec_pub_der,
            meta={
                "gen_ms": t.elapsed_ms,
                "kex_public_key_bytes": len(x_pub),
                "sig_public_key_bytes": len(ec_pub_der),
                "kex_algorithm": self.kex_algorithm,
                "sig_algorithm": self.sig_algorithm,
            },
        )

    def accept(self, handshake_id: str, kex_blob: bytes) -> tuple[bytes, dict]:
        state = self._sessions[handshake_id]
        if len(kex_blob) != X25519_PUBLIC_KEY_BYTES:
            raise ValueError(f"X25519 kex blob must be {X25519_PUBLIC_KEY_BYTES} bytes, got {len(kex_blob)}")
        with Timer() as t:
            raw_secret = state.x25519_private.exchange(X25519PublicKey.from_public_bytes(kex_blob))
            session_key = derive_session_key(raw_secret, context=_HKDF_CONTEXT)
        return session_key, {"decapsulate_ms": t.elapsed_ms, "kex_blob_bytes": len(kex_blob)}

    def sign(self, handshake_id: str, message: bytes) -> tuple[bytes, dict]:
        state = self._sessions[handshake_id]
        with Timer() as t:
            signature = state.ec_private.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature, {"sign_ms": t.elapsed_ms, "sign_cpu_ms": t.cpu_ms, "signature_bytes": len(signature)}

    def forget(self, handshake_id: str) -> None:
        self._sessions.pop(handshake_id, None)


class ClassicalECDHEClientCrypto(ClientCryptoConfig):
    name = "classical_ecdhe"

    def establish(self, kex_public_key: bytes) -> EstablishResult:
        if len(kex_public_key) != X25519_PUBLIC_KEY_BYTES:
            raise ValueError(f"X25519 public key must be {X25519_PUBLIC_KEY_BYTES} bytes, got {len(kex_public_key)}")
        with Timer() as t:
            x_private = X25519PrivateKey.generate()
            raw_secret = x_private.exchange(X25519PublicKey.from_public_bytes(kex_public_key))
            session_key = derive_session_key(raw_secret, context=_HKDF_CONTEXT)
            kex_blob = _x25519_raw(x_private.public_key())
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
        return ok, {"verify_ms": t.elapsed_ms, "verify_cpu_ms": t.cpu_ms}
