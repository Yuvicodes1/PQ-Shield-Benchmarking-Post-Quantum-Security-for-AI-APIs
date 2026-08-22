"""Shared contract implemented identically by classical.py, hybrid.py, and
full_pqc.py, so that api/server_config_{a,b,c}.py and the bench orchestrator
can swap configurations by import alone -- no branching logic elsewhere.

Every configuration produces the same four request/response artifacts:
  - a handshake bundle (server's ephemeral public key material + timing/size metadata)
  - a client-side "establish" step (produce a session key + wire-format key-establishment blob)
  - a server-side "accept" step (recover the session key from the blob)
  - sign/verify over the AES-GCM response envelope

All three configs share AES-256-GCM for payload confidentiality (crypto/aead.py);
they differ only in how the AES key is established and how responses are signed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class HandshakeBundle:
    """What GET /secure/handshake returns (server -> client)."""
    handshake_id: str
    kex_public_key: bytes          # RSA pub (classical) or ML-KEM-768 pub (hybrid/full-pqc)
    sig_public_key: bytes          # ECDSA pub (classical/hybrid) or ML-DSA-65 pub (full-pqc)
    meta: dict = field(default_factory=dict)   # gen_ms, key_bytes, algorithm names


@dataclass
class EstablishResult:
    """What the client produces locally when establishing a session (does not go over the wire as-is)."""
    session_key: bytes
    kex_blob: bytes                # RSA-OAEP ciphertext (classical) or ML-KEM ciphertext (hybrid/full-pqc)
    meta: dict = field(default_factory=dict)   # handshake_ms, ciphertext_bytes


class ServerCryptoConfig(ABC):
    """Server-side half of a configuration. One instance = one live key pair set."""

    name: str
    kex_algorithm: str
    sig_algorithm: str

    @abstractmethod
    def new_handshake(self, handshake_id: str) -> HandshakeBundle:
        """Generate a fresh ephemeral key pair set and return the public bundle.

        Called once per /secure/handshake request -- this project's default
        benchmarking mode is a *fresh* handshake per client transaction
        (the conservative, worst-case measurement; see docs/DESIGN.md #4.2).
        """
        raise NotImplementedError

    @abstractmethod
    def accept(self, handshake_id: str, kex_blob: bytes) -> tuple[bytes, dict]:
        """Recover the AES session key for a previously issued handshake_id.

        Returns (session_key, meta) where meta includes decapsulation/decrypt timing.
        """
        raise NotImplementedError

    @abstractmethod
    def sign(self, handshake_id: str, message: bytes) -> tuple[bytes, dict]:
        """Sign `message` (the response AEAD envelope) with this handshake's signing key.

        Returns (signature, meta).
        """
        raise NotImplementedError

    @abstractmethod
    def forget(self, handshake_id: str) -> None:
        """Drop server-side state for a handshake_id (call after replying, to bound memory)."""
        raise NotImplementedError


class ClientCryptoConfig(ABC):
    """Client-side half of a configuration. Stateless across handshakes."""

    name: str

    @abstractmethod
    def establish(self, kex_public_key: bytes) -> EstablishResult:
        """Produce a fresh session key + the key-establishment blob to send to the server."""
        raise NotImplementedError

    @abstractmethod
    def verify(self, message: bytes, signature: bytes, sig_public_key: bytes) -> tuple[bool, dict]:
        """Verify a server signature over `message`. Returns (valid, meta)."""
        raise NotImplementedError
