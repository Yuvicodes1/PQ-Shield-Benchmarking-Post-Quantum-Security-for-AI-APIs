"""Configuration B' -- Hybrid-KEX: X25519MLKEM768 key exchange + ECDSA P-256.

Key establishment combines both algorithms in one exchange, following the
construction of draft-ietf-tls-ecdhe-mlkem (the X25519MLKEM768 group that
browsers and CDNs negotiate today):

  server key share   = ML-KEM-768 encapsulation key (1,184 B) || X25519 public key (32 B)
  client key share   = ML-KEM-768 ciphertext (1,088 B)        || X25519 public key (32 B)
  shared secret      = ML-KEM-768 shared secret (32 B)        || X25519 shared secret (32 B)

and the session key is HKDF-SHA256 over that 64-byte concatenation. An
attacker must break BOTH ML-KEM-768 and X25519 to recover it, so it stays
secure if either one falls -- the defence-in-depth argument for hybrids.

Signatures: ECDSA P-256, identical to Configuration B (Hybrid, ML-KEM-only key
exchange) and A' (Classical-ECDHE), so:
  * A' -> B' adds ML-KEM-768 to X25519 (the actual deployed migration step);
  * B  -> B' adds X25519 to ML-KEM-768 (the cost of hedging against an
    ML-KEM break).

This module is a benchmarking analogue of the TLS group, not an
implementation of the TLS key schedule.
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
from .oqs_adapter import MLKEM768

X25519_BYTES = 32
_HKDF_CONTEXT = b"pq-shield-hybrid-kex-x25519mlkem768"


def _ec_public_der(pub) -> bytes:
    return pub.public_bytes(encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo)


def _x25519_raw(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


@dataclass
class _HandshakeState:
    kem_secret_key: bytes
    x25519_private: X25519PrivateKey
    ec_private: ec.EllipticCurvePrivateKey


class HybridKEXServerCrypto(ServerCryptoConfig):
    name = "hybrid_kex"
    kex_algorithm = "X25519MLKEM768"
    sig_algorithm = "ECDSA-P256-SHA256"

    def __init__(self) -> None:
        self._sessions: dict[str, _HandshakeState] = {}

    def new_handshake(self, handshake_id: str | None = None) -> HandshakeBundle:
        handshake_id = handshake_id or str(uuid.uuid4())
        with Timer() as t:
            kem_kp = MLKEM768.keypair()
            x_private = X25519PrivateKey.generate()
            ec_private = ec.generate_private_key(ec.SECP256R1())
        self._sessions[handshake_id] = _HandshakeState(kem_kp.secret_key, x_private, ec_private)

        kex_pub = kem_kp.public_key + _x25519_raw(x_private.public_key())
        ec_pub_der = _ec_public_der(ec_private.public_key())
        return HandshakeBundle(
            handshake_id=handshake_id,
            kex_public_key=kex_pub,
            sig_public_key=ec_pub_der,
            meta={
                "gen_ms": t.elapsed_ms,
                "kex_public_key_bytes": len(kex_pub),
                "sig_public_key_bytes": len(ec_pub_der),
                "kex_algorithm": self.kex_algorithm,
                "sig_algorithm": self.sig_algorithm,
            },
        )

    def accept(self, handshake_id: str, kex_blob: bytes) -> tuple[bytes, dict]:
        state = self._sessions[handshake_id]
        ct_len = MLKEM768.CIPHERTEXT_BYTES
        if len(kex_blob) != ct_len + X25519_BYTES:
            raise ValueError(f"X25519MLKEM768 kex blob must be {ct_len + X25519_BYTES} bytes, got {len(kex_blob)}")
        with Timer() as t:
            kem_ss = MLKEM768.decaps(kex_blob[:ct_len], state.kem_secret_key)
            x_ss = state.x25519_private.exchange(X25519PublicKey.from_public_bytes(kex_blob[ct_len:]))
            session_key = derive_session_key(kem_ss + x_ss, context=_HKDF_CONTEXT)
        return session_key, {"decapsulate_ms": t.elapsed_ms, "kex_blob_bytes": len(kex_blob)}

    def sign(self, handshake_id: str, message: bytes) -> tuple[bytes, dict]:
        state = self._sessions[handshake_id]
        with Timer() as t:
            signature = state.ec_private.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature, {"sign_ms": t.elapsed_ms, "sign_cpu_ms": t.cpu_ms, "signature_bytes": len(signature)}

    def forget(self, handshake_id: str) -> None:
        self._sessions.pop(handshake_id, None)


class HybridKEXClientCrypto(ClientCryptoConfig):
    name = "hybrid_kex"

    def establish(self, kex_public_key: bytes) -> EstablishResult:
        pk_len = MLKEM768.PUBLIC_KEY_BYTES
        if len(kex_public_key) != pk_len + X25519_BYTES:
            raise ValueError(f"X25519MLKEM768 key share must be {pk_len + X25519_BYTES} bytes, "
                             f"got {len(kex_public_key)}")
        with Timer() as t:
            kem_ct, kem_ss = MLKEM768.encaps(kex_public_key[:pk_len])
            x_private = X25519PrivateKey.generate()
            x_ss = x_private.exchange(X25519PublicKey.from_public_bytes(kex_public_key[pk_len:]))
            session_key = derive_session_key(kem_ss + x_ss, context=_HKDF_CONTEXT)
            kex_blob = kem_ct + _x25519_raw(x_private.public_key())
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
