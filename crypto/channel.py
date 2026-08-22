"""The stable interface all Config A/B/C cryptographic wrappers implement."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class HandshakeMaterial:
    key_exchange_public_key: str
    signing_public_key: str
    algorithm: str


class CryptoChannel(ABC):
    @abstractmethod
    def handshake(self) -> HandshakeMaterial:
        """Return public material a client needs for a protected exchange."""

    @abstractmethod
    def decrypt_request(self, encrypted_key: bytes, envelope: bytes) -> bytes:
        """Open an encrypted request and return its plaintext bytes."""

    @abstractmethod
    def encrypt_and_sign_response(self, plaintext: bytes) -> tuple[bytes, bytes]:
        """Return (AES-GCM envelope, signature) for a response."""
