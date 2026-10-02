"""Configuration C' -- Hybrid-KEX-PQ: X25519MLKEM768 key exchange + ML-DSA-65.

The combination Full PQC (C) and Hybrid-KEX (B') point to: key establishment
hedged against an ML-KEM break exactly as in B' (see crypto/hybrid_kex.py),
and post-quantum signatures exactly as in C. Relative to C it adds X25519 to
the key exchange; relative to B' it replaces ECDSA P-256 with ML-DSA-65.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .base import HandshakeBundle
from .hybrid_kex import HybridKEXClientCrypto, HybridKEXServerCrypto, _x25519_raw
from .instrumentation import Timer
from .oqs_adapter import MLDSA65, MLKEM768


@dataclass
class _HandshakeState:
    kem_secret_key: bytes
    x25519_private: X25519PrivateKey
    sig_secret_key: bytes


class HybridKEXPQServerCrypto(HybridKEXServerCrypto):
    name = "hybrid_kex_pq"
    kex_algorithm = "X25519MLKEM768"
    sig_algorithm = MLDSA65.ALGORITHM

    def new_handshake(self, handshake_id: str | None = None) -> HandshakeBundle:
        handshake_id = handshake_id or str(uuid.uuid4())
        with Timer() as t:
            kem_kp = MLKEM768.keypair()
            x_private = X25519PrivateKey.generate()
            sig_kp = MLDSA65.keypair()
        self._sessions[handshake_id] = _HandshakeState(kem_kp.secret_key, x_private, sig_kp.secret_key)

        kex_pub = kem_kp.public_key + _x25519_raw(x_private.public_key())
        return HandshakeBundle(
            handshake_id=handshake_id,
            kex_public_key=kex_pub,
            sig_public_key=sig_kp.public_key,
            meta={
                "gen_ms": t.elapsed_ms,
                "kex_public_key_bytes": len(kex_pub),
                "sig_public_key_bytes": len(sig_kp.public_key),
                "kex_algorithm": self.kex_algorithm,
                "sig_algorithm": self.sig_algorithm,
            },
        )

    # accept() is inherited: it reads only kem_secret_key and x25519_private.

    def sign(self, handshake_id: str, message: bytes) -> tuple[bytes, dict]:
        state = self._sessions[handshake_id]
        with Timer() as t:
            signature = MLDSA65.sign(message, state.sig_secret_key)
        return signature, {"sign_ms": t.elapsed_ms, "sign_cpu_ms": t.cpu_ms, "signature_bytes": len(signature)}


class HybridKEXPQClientCrypto(HybridKEXClientCrypto):
    name = "hybrid_kex_pq"

    # establish() is inherited (X25519MLKEM768).

    def verify(self, message: bytes, signature: bytes, sig_public_key: bytes) -> tuple[bool, dict]:
        with Timer() as t:
            ok = MLDSA65.verify(message, signature, sig_public_key)
        return ok, {"verify_ms": t.elapsed_ms, "verify_cpu_ms": t.cpu_ms}
