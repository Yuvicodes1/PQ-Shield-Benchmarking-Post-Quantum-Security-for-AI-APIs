"""Configuration C -- Full Post-Quantum.

Key establishment: ML-KEM-768 (FIPS 203) encapsulation.
Signatures: ML-DSA-65 (FIPS 204) -- quantum-resistant for both confidentiality
and integrity/authenticity, at the cost of much larger public keys and
signatures than ECDSA (see crypto/oqs_adapter.py byte-length constants).

H4 (design doc) predicts ML-DSA-65 *verification* should not be a latency
regression versus ECDSA despite the byte-size increase, because lattice
verification is comparatively cheap arithmetic. That is an empirical
question this configuration exists to answer, not an assumption baked in
here -- the sign/verify calls below are timed identically to classical.py
and hybrid.py so the numbers are directly comparable.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from .aead import derive_session_key
from .base import ClientCryptoConfig, EstablishResult, HandshakeBundle, ServerCryptoConfig
from .instrumentation import Timer
from .oqs_adapter import MLDSA65, MLKEM768


@dataclass
class _HandshakeState:
    kem_secret_key: bytes
    sig_secret_key: bytes


class FullPQCServerCrypto(ServerCryptoConfig):
    name = "full_pqc"
    kex_algorithm = MLKEM768.ALGORITHM
    sig_algorithm = MLDSA65.ALGORITHM

    def __init__(self) -> None:
        self._sessions: dict[str, _HandshakeState] = {}

    def new_handshake(self, handshake_id: str | None = None) -> HandshakeBundle:
        handshake_id = handshake_id or str(uuid.uuid4())
        with Timer() as t:
            kem_kp = MLKEM768.keypair()
            sig_kp = MLDSA65.keypair()
        self._sessions[handshake_id] = _HandshakeState(kem_kp.secret_key, sig_kp.secret_key)

        return HandshakeBundle(
            handshake_id=handshake_id,
            kex_public_key=kem_kp.public_key,
            sig_public_key=sig_kp.public_key,
            meta={
                "gen_ms": t.elapsed_ms,
                "kex_public_key_bytes": len(kem_kp.public_key),
                "sig_public_key_bytes": len(sig_kp.public_key),
                "kex_algorithm": self.kex_algorithm,
                "sig_algorithm": self.sig_algorithm,
            },
        )

    def accept(self, handshake_id: str, kex_blob: bytes) -> tuple[bytes, dict]:
        state = self._sessions[handshake_id]
        with Timer() as t:
            raw_secret = MLKEM768.decaps(kex_blob, state.kem_secret_key)
            session_key = derive_session_key(raw_secret, context=b"pq-shield-full-pqc")
        return session_key, {"decapsulate_ms": t.elapsed_ms, "kex_blob_bytes": len(kex_blob)}

    def sign(self, handshake_id: str, message: bytes) -> tuple[bytes, dict]:
        state = self._sessions[handshake_id]
        with Timer() as t:
            signature = MLDSA65.sign(message, state.sig_secret_key)
        return signature, {"sign_ms": t.elapsed_ms, "signature_bytes": len(signature)}

    def forget(self, handshake_id: str) -> None:
        self._sessions.pop(handshake_id, None)


class FullPQCClientCrypto(ClientCryptoConfig):
    name = "full_pqc"

    def establish(self, kex_public_key: bytes) -> EstablishResult:
        with Timer() as t:
            kex_blob, raw_secret = MLKEM768.encaps(kex_public_key)
            session_key = derive_session_key(raw_secret, context=b"pq-shield-full-pqc")
        return EstablishResult(
            session_key=session_key,
            kex_blob=kex_blob,
            meta={"handshake_encrypt_ms": t.elapsed_ms, "kex_blob_bytes": len(kex_blob)},
        )

    def verify(self, message: bytes, signature: bytes, sig_public_key: bytes) -> tuple[bool, dict]:
        with Timer() as t:
            ok = MLDSA65.verify(message, signature, sig_public_key)
        return ok, {"verify_ms": t.elapsed_ms}
