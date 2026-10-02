"""Optional handshake authentication: a long-term server identity key signs
each handshake transcript, and a client that has pinned the identity public
key rejects any handshake whose transcript signature does not verify.

Without this, the handshake is unauthenticated: an on-path attacker can
replace the server's key shares with its own, terminate both legs, read every
request, and re-sign forged responses with a signing key it chose (measured
by threats/key_substitution.py). This is the role certificates and
CertificateVerify play in TLS 1.3; here the identity key is pinned out of
band (fetched once from GET /secure/identity, standing in for a certificate
chain), not validated through a PKI.

The identity scheme follows the configuration's signature algorithm: ECDSA
P-256 for configurations that sign with ECDSA, ML-DSA-65 for those that sign
with ML-DSA-65 -- so a post-quantum configuration stays post-quantum.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .instrumentation import Timer
from .oqs_adapter import MLDSA65

DOMAIN = b"PQ-Shield-handshake-v1"
ECDSA = "ECDSA-P256-SHA256"


def _field(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def transcript(handshake_id: str, kex_algorithm: str, sig_algorithm: str,
               kex_public_key: bytes, sig_public_key: bytes) -> bytes:
    """Everything the client relies on from the handshake, length-prefixed so
    no two distinct transcripts serialize identically."""
    return hashlib.sha256(
        DOMAIN + b"\x00" + _field(handshake_id.encode()) + _field(kex_algorithm.encode())
        + _field(sig_algorithm.encode()) + _field(kex_public_key) + _field(sig_public_key)
    ).digest()


def identity_algorithm_for(sig_algorithm: str) -> str:
    return MLDSA65.ALGORITHM if sig_algorithm == MLDSA65.ALGORITHM else ECDSA


@dataclass
class IdentityKey:
    algorithm: str
    public_key: bytes
    _secret: object

    @classmethod
    def generate(cls, algorithm: str) -> "IdentityKey":
        if algorithm == MLDSA65.ALGORITHM:
            kp = MLDSA65.keypair()
            return cls(algorithm, kp.public_key, kp.secret_key)
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key().public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
        return cls(ECDSA, pub, priv)

    def sign(self, message: bytes) -> tuple[bytes, dict]:
        with Timer() as t:
            if self.algorithm == MLDSA65.ALGORITHM:
                sig = MLDSA65.sign(message, self._secret)
            else:
                sig = self._secret.sign(message, ec.ECDSA(hashes.SHA256()))
        return sig, {"sign_ms": t.elapsed_ms, "sign_cpu_ms": t.cpu_ms}


def verify_identity(algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> tuple[bool, dict]:
    with Timer() as t:
        if algorithm == MLDSA65.ALGORITHM:
            ok = MLDSA65.verify(message, signature, public_key)
        else:
            try:
                serialization.load_der_public_key(public_key).verify(signature, message, ec.ECDSA(hashes.SHA256()))
                ok = True
            except Exception:
                ok = False
    return ok, {"verify_ms": t.elapsed_ms, "verify_cpu_ms": t.cpu_ms}


def verify_handshake(handshake_json: dict, pinned: dict, b64decode) -> tuple[bool, dict]:
    """Client-side check of a /secure/handshake response against a pinned
    identity ({"algorithm", "public_key"(bytes)}). A missing signature fails."""
    sig_b64 = handshake_json.get("transcript_signature")
    if not sig_b64:
        return False, {"verify_ms": 0.0, "reason": "no transcript signature"}
    msg = transcript(handshake_json["handshake_id"], handshake_json["kex_algorithm"],
                     handshake_json["sig_algorithm"], b64decode(handshake_json["kex_public_key"]),
                     b64decode(handshake_json["sig_public_key"]))
    return verify_identity(pinned["algorithm"], pinned["public_key"], msg, b64decode(sig_b64))
