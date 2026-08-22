"""Configuration B -- Pragmatic Hybrid.

Key establishment: ML-KEM-768 (FIPS 203) encapsulation -- quantum-resistant,
closes the HNDL attack surface for confidentiality of harvested traffic.

Signatures: ECDSA P-256 -- classical, kept for now per the industry's actual
current migration guidance (see docs/DESIGN.md #2.2): signatures protect
real-time integrity, not the confidentiality of stored/harvested traffic, so
the argument for paying the larger ML-DSA signature cost immediately is
weaker than the argument for immediately paying the ML-KEM cost.

This is the "incremental migration path" configuration H2 is about: it
should capture most of Full PQC's quantum-resistance benefit against HNDL
while costing less than Full PQC in aggregate latency, because ECDSA signing
stays cheap.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

from .aead import derive_session_key
from .base import ClientCryptoConfig, EstablishResult, HandshakeBundle, ServerCryptoConfig
from .instrumentation import Timer
from .oqs_adapter import MLKEM768


def _ec_public_der(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@dataclass
class _HandshakeState:
    kem_secret_key: bytes
    ec_private: ec.EllipticCurvePrivateKey


class HybridServerCrypto(ServerCryptoConfig):
    name = "hybrid"
    kex_algorithm = MLKEM768.ALGORITHM
    sig_algorithm = "ECDSA-P256-SHA256"

    def __init__(self) -> None:
        self._sessions: dict[str, _HandshakeState] = {}

    def new_handshake(self, handshake_id: str | None = None) -> HandshakeBundle:
        handshake_id = handshake_id or str(uuid.uuid4())
        with Timer() as t:
            kem_kp = MLKEM768.keypair()
            ec_private = ec.generate_private_key(ec.SECP256R1())
        self._sessions[handshake_id] = _HandshakeState(kem_kp.secret_key, ec_private)

        ec_pub_der = _ec_public_der(ec_private.public_key())
        return HandshakeBundle(
            handshake_id=handshake_id,
            kex_public_key=kem_kp.public_key,
            sig_public_key=ec_pub_der,
            meta={
                "gen_ms": t.elapsed_ms,
                "kex_public_key_bytes": len(kem_kp.public_key),
                "sig_public_key_bytes": len(ec_pub_der),
                "kex_algorithm": self.kex_algorithm,
                "sig_algorithm": self.sig_algorithm,
            },
        )

    def accept(self, handshake_id: str, kex_blob: bytes) -> tuple[bytes, dict]:
        state = self._sessions[handshake_id]
        with Timer() as t:
            raw_secret = MLKEM768.decaps(kex_blob, state.kem_secret_key)
            session_key = derive_session_key(raw_secret, context=b"pq-shield-hybrid")
        return session_key, {"decapsulate_ms": t.elapsed_ms, "kex_blob_bytes": len(kex_blob)}

    def sign(self, handshake_id: str, message: bytes) -> tuple[bytes, dict]:
        state = self._sessions[handshake_id]
        with Timer() as t:
            signature = state.ec_private.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature, {"sign_ms": t.elapsed_ms, "signature_bytes": len(signature)}

    def forget(self, handshake_id: str) -> None:
        self._sessions.pop(handshake_id, None)


class HybridClientCrypto(ClientCryptoConfig):
    name = "hybrid"

    def establish(self, kex_public_key: bytes) -> EstablishResult:
        with Timer() as t:
            kex_blob, raw_secret = MLKEM768.encaps(kex_public_key)
            session_key = derive_session_key(raw_secret, context=b"pq-shield-hybrid")
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
