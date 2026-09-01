"""Signing strategies for streaming (chunked) protected responses -- e.g. an
LLM chat-completion API's token-by-token SSE stream, where the full response
does not exist yet at the moment the first bytes must leave the server.

THE PROBLEM THIS FILE ANSWERS
------------------------------
Every configuration elsewhere in this project (crypto/classical.py,
hybrid.py, full_pqc.py) signs one complete response in one call. That
assumes the whole response exists before any of it is sent -- true for a
classifier's single JSON reply, false for a token-by-token LLM stream. You
cannot sign bytes you have not generated yet. Three different answers to
that, each with a different cost:

  BUFFER_AND_SIGN
    Wait for the whole response, encrypt + sign once, then send it.
    Cheapest in signature bytes (exactly one signature, same as every other
    configuration in this project). Worst possible time-to-first-byte: the
    client waits for the *entire* generation before receiving anything --
    streaming is defeated in every way that matters to a user.

  PER_CHUNK
    Encrypt + sign every chunk independently, the instant it is generated.
    Best time-to-first-byte (the first chunk ships as soon as it exists).
    Worst signature overhead: N signatures for N chunks. For ML-DSA-65
    (3,309 bytes/signature) at one-token-per-chunk over a 500-token
    response, that is >1.6 MB of signatures alone -- see
    docs/STREAMING.md for the measured figures.

  HASH_CHAIN
    Encrypt every chunk immediately (AES-GCM already authenticates each
    chunk's own bytes the instant it arrives -- that guarantee does not
    depend on signing at all). Chunks are additionally folded into a
    running SHA-256 hash chain; only the *final* chain hash is signed
    (optionally also at periodic checkpoints). This amortizes the
    expensive signature operation across the whole stream, at the cost of
    deferring the *sequence-integrity* guarantee (every chunk present,
    none dropped, none reordered) until the terminating signature arrives.
    Per-chunk tamper detection is still immediate via AEAD; it is only the
    "this is the complete, correctly-ordered stream" guarantee that waits.

A SUBTLE PITFALL THIS DESIGN DELIBERATELY CLOSES
--------------------------------------------------
A naive PER_CHUNK implementation signs only `nonce || ciphertext` per
chunk. Every individual chunk still verifies correctly under that scheme --
but nothing stops an active adversary from **reordering or dropping**
independently-valid signed chunks, since no chunk's signature says
anything about its position in the sequence. Two chunks silently swapped
would each still pass signature verification.

PER_CHUNK here instead signs `index || nonce || ciphertext` (the 4-byte
big-endian chunk index is bound into what gets signed), and the client
independently tracks an expected running index and flags any gap or
out-of-order arrival. Reordering now breaks either the signature check
(if an attacker also tries to relabel the index) or the sequence check (if
they do not). See test_streaming_signing.py::test_per_chunk_detects_reordering.

HASH_CHAIN is not vulnerable to this in the first place: each link folds in
the previous link's hash, so reordering or dropping any chunk changes every
subsequent hash, which the terminating signature over the final hash then
catches deterministically.

All three strategies reuse the existing ServerCryptoConfig.sign() /
ClientCryptoConfig.verify() from crypto/base.py -- no new cryptographic
primitive is introduced, only a different schedule for calling the existing
one.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from crypto.aead import AEADError, aead_decrypt, aead_encrypt
from crypto.base import ClientCryptoConfig, ServerCryptoConfig

GENESIS_HASH = b"\x00" * 32


def _index_bytes(index: int) -> bytes:
    return index.to_bytes(4, "big")


# ---------------------------------------------------------------------------
# Server side
# ---------------------------------------------------------------------------

class StreamSigningStrategy(ABC):
    """Server-side. One instance per streaming transaction."""

    name: str

    @abstractmethod
    def add_chunk(self, plaintext: bytes, index: int) -> dict | None:
        """Called once per generated chunk, in order, starting at index 0.
        Returns a wire-ready dict to send immediately, or None if this
        strategy withholds output until finalize()."""
        raise NotImplementedError

    @abstractmethod
    def finalize(self, n_chunks: int) -> dict | None:
        """Called exactly once after the last chunk. Returns a final
        wire-ready dict (e.g. the buffered envelope+signature, or the
        terminating signed chain hash), or None if nothing more is needed."""
        raise NotImplementedError


class BufferAndSignStrategy(StreamSigningStrategy):
    name = "buffer_and_sign"

    def __init__(self, server_crypto: ServerCryptoConfig, handshake_id: str, session_key: bytes):
        self._server_crypto = server_crypto
        self._handshake_id = handshake_id
        self._session_key = session_key
        self._buffer = bytearray()

    def add_chunk(self, plaintext: bytes, index: int) -> dict | None:
        self._buffer.extend(plaintext)
        return None

    def finalize(self, n_chunks: int) -> dict | None:
        aead = aead_encrypt(self._session_key, bytes(self._buffer))
        envelope = aead.nonce + aead.ciphertext
        signature, meta = self._server_crypto.sign(self._handshake_id, envelope)
        return {
            "kind": "final_buffered",
            "nonce": aead.nonce,
            "ciphertext": aead.ciphertext,
            "signature": signature,
            "sign_ms": meta["sign_ms"],
            "signature_bytes": len(signature),
        }


class PerChunkStrategy(StreamSigningStrategy):
    name = "per_chunk"

    def __init__(self, server_crypto: ServerCryptoConfig, handshake_id: str, session_key: bytes):
        self._server_crypto = server_crypto
        self._handshake_id = handshake_id
        self._session_key = session_key

    def add_chunk(self, plaintext: bytes, index: int) -> dict | None:
        aead = aead_encrypt(self._session_key, plaintext)
        envelope = aead.nonce + aead.ciphertext
        signed_bytes = _index_bytes(index) + envelope  # binds sequence position -- see module docstring
        signature, meta = self._server_crypto.sign(self._handshake_id, signed_bytes)
        return {
            "kind": "chunk",
            "index": index,
            "nonce": aead.nonce,
            "ciphertext": aead.ciphertext,
            "signature": signature,
            "sign_ms": meta["sign_ms"],
            "signature_bytes": len(signature),
        }

    def finalize(self, n_chunks: int) -> dict | None:
        return None


class HashChainStrategy(StreamSigningStrategy):
    name = "hash_chain"

    def __init__(
        self,
        server_crypto: ServerCryptoConfig,
        handshake_id: str,
        session_key: bytes,
        checkpoint_interval: int | None = None,
    ):
        self._server_crypto = server_crypto
        self._handshake_id = handshake_id
        self._session_key = session_key
        self._checkpoint_interval = checkpoint_interval
        self._running_hash = GENESIS_HASH
        self._since_checkpoint = 0

    def add_chunk(self, plaintext: bytes, index: int) -> dict | None:
        aead = aead_encrypt(self._session_key, plaintext)
        envelope = aead.nonce + aead.ciphertext
        self._running_hash = hashlib.sha256(self._running_hash + _index_bytes(index) + envelope).digest()
        self._since_checkpoint += 1

        row = {
            "kind": "chunk",
            "index": index,
            "nonce": aead.nonce,
            "ciphertext": aead.ciphertext,
            "chain_hash": self._running_hash,
            "signature": None,
            "sign_ms": 0.0,
            "signature_bytes": 0,
        }
        if self._checkpoint_interval and self._since_checkpoint >= self._checkpoint_interval:
            signature, meta = self._server_crypto.sign(self._handshake_id, self._running_hash)
            row["signature"] = signature
            row["sign_ms"] = meta["sign_ms"]
            row["signature_bytes"] = len(signature)
            self._since_checkpoint = 0
        return row

    def finalize(self, n_chunks: int) -> dict | None:
        # Always sign the final chain hash, regardless of the checkpoint
        # schedule, so the stream is fully verifiable end-to-end even if
        # checkpoint_interval never divided n_chunks evenly.
        signature, meta = self._server_crypto.sign(self._handshake_id, self._running_hash)
        return {
            "kind": "final_chain",
            "final_chain_hash": self._running_hash,
            "n_chunks": n_chunks,
            "signature": signature,
            "sign_ms": meta["sign_ms"],
            "signature_bytes": len(signature),
        }


SERVER_STRATEGIES = {
    "buffer_and_sign": BufferAndSignStrategy,
    "per_chunk": PerChunkStrategy,
    "hash_chain": HashChainStrategy,
}
STRATEGY_NAMES = list(SERVER_STRATEGIES.keys())


def get_server_strategy(name: str, server_crypto, handshake_id: str, session_key: bytes, **kwargs):
    if name not in SERVER_STRATEGIES:
        raise ValueError(f"Unknown streaming strategy '{name}'. Valid: {STRATEGY_NAMES}")
    return SERVER_STRATEGIES[name](server_crypto, handshake_id, session_key, **kwargs)


# ---------------------------------------------------------------------------
# Client side
# ---------------------------------------------------------------------------

@dataclass
class HashChainClientState:
    """Tracks the client's own recomputation of the hash chain as chunks
    arrive, so it can be compared against the server's claimed final hash."""

    running_hash: bytes = field(default=GENESIS_HASH)

    def absorb(self, index: int, nonce: bytes, ciphertext: bytes) -> bytes:
        envelope = nonce + ciphertext
        self.running_hash = hashlib.sha256(self.running_hash + _index_bytes(index) + envelope).digest()
        return self.running_hash


def verify_buffer_and_sign_final(final_chunk: dict, session_key: bytes, sig_public_key: bytes,
                                  client_crypto: ClientCryptoConfig) -> dict:
    envelope = final_chunk["nonce"] + final_chunk["ciphertext"]
    valid, meta = client_crypto.verify(envelope, final_chunk["signature"], sig_public_key)
    result = {"signature_valid": valid, "verify_ms": meta["verify_ms"], "aead_ok": None, "plaintext": None}
    if valid:
        try:
            result["plaintext"] = aead_decrypt(session_key, final_chunk["nonce"], final_chunk["ciphertext"])
            result["aead_ok"] = True
        except AEADError:
            result["aead_ok"] = False
    return result


def verify_per_chunk(chunk: dict, expected_index: int, session_key: bytes, sig_public_key: bytes,
                      client_crypto: ClientCryptoConfig) -> dict:
    envelope = chunk["nonce"] + chunk["ciphertext"]
    signed_bytes = _index_bytes(chunk["index"]) + envelope
    valid, meta = client_crypto.verify(signed_bytes, chunk["signature"], sig_public_key)
    result = {
        "index": chunk["index"],
        "signature_valid": valid,
        "verify_ms": meta["verify_ms"],
        "in_order": chunk["index"] == expected_index,
        "aead_ok": None,
        "plaintext": None,
    }
    if valid:
        try:
            result["plaintext"] = aead_decrypt(session_key, chunk["nonce"], chunk["ciphertext"])
            result["aead_ok"] = True
        except AEADError:
            result["aead_ok"] = False
    return result


def verify_hash_chain_chunk(chunk: dict, chain_state: HashChainClientState, session_key: bytes) -> dict:
    expected_hash = chain_state.absorb(chunk["index"], chunk["nonce"], chunk["ciphertext"])
    result = {
        "index": chunk["index"],
        "chain_ok_so_far": expected_hash == chunk["chain_hash"],
        "aead_ok": None,
        "plaintext": None,
    }
    try:
        result["plaintext"] = aead_decrypt(session_key, chunk["nonce"], chunk["ciphertext"])
        result["aead_ok"] = True
    except AEADError:
        result["aead_ok"] = False
    return result


def verify_hash_chain_final(final_chunk: dict, chain_state: HashChainClientState, sig_public_key: bytes,
                             client_crypto: ClientCryptoConfig) -> dict:
    chain_matches = final_chunk["final_chain_hash"] == chain_state.running_hash
    valid, meta = client_crypto.verify(chain_state.running_hash, final_chunk["signature"], sig_public_key)
    return {
        "chain_matches_client_computed": chain_matches,
        "signature_valid": valid,
        "verify_ms": meta["verify_ms"],
        "stream_fully_verified": chain_matches and valid,
    }
