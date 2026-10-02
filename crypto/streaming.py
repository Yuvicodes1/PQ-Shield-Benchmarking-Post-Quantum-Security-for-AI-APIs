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

SESSION BINDING, DOMAIN SEPARATION, AND TERMINATION (v2)
--------------------------------------------------------
Every signed message starts with a 3-byte label naming its role and a
32-byte session context ctx = SHA-256("PQ-Shield-stream-v2" || 0x00 ||
handshake_id), so a signature made for one purpose or one stream can never
verify as another:

  buffer_and_sign  sign("BUF" || ctx || nonce || ciphertext)
  per_chunk        sign("CHK" || ctx || index || nonce || ciphertext) per chunk,
                   then sign("END" || ctx || n_chunks) as a terminal record
  hash_chain       h_0 = SHA-256("GEN" || ctx);
                   h_i = SHA-256(h_{i-1} || index || nonce || ciphertext);
                   checkpoint: sign("CKP" || ctx || index || h_i);
                   final:      sign("FIN" || ctx || n_chunks || h_n)

Binding ctx makes cross-stream replay fail even if the server's signing key
were long-term (today it is per-handshake, which also prevents it). The
terminal records bind the stream length, so a truncated stream -- tail
chunks dropped, with or without the terminal record -- is never reported as
fully verified: the client requires the terminal record and checks its count.

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

DOMAIN = b"PQ-Shield-stream-v2"
PROTOCOL_VERSION = "v2"  # recorded with every streaming row; v1 had no context binding or end records


def _index_bytes(index: int) -> bytes:
    return index.to_bytes(4, "big")


def stream_context(handshake_id: str) -> bytes:
    """32-byte session context bound into every signed streaming message."""
    return hashlib.sha256(DOMAIN + b"\x00" + handshake_id.encode()).digest()


def genesis_hash(handshake_id: str) -> bytes:
    """Session-specific h_0 for the hash chain (a fixed all-zero genesis would
    make chains from different sessions start identically)."""
    return hashlib.sha256(b"GEN" + stream_context(handshake_id)).digest()


def buffered_message(ctx: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return b"BUF" + ctx + nonce + ciphertext


def chunk_message(ctx: bytes, index: int, nonce: bytes, ciphertext: bytes) -> bytes:
    return b"CHK" + ctx + _index_bytes(index) + nonce + ciphertext


def end_message(ctx: bytes, n_chunks: int) -> bytes:
    return b"END" + ctx + _index_bytes(n_chunks)


def checkpoint_message(ctx: bytes, index: int, chain_hash: bytes) -> bytes:
    return b"CKP" + ctx + _index_bytes(index) + chain_hash


def final_chain_message(ctx: bytes, n_chunks: int, chain_hash: bytes) -> bytes:
    return b"FIN" + ctx + _index_bytes(n_chunks) + chain_hash


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
        """Called exactly once after the last chunk. Returns the final
        wire-ready dict (buffered envelope, per-chunk end record, or
        terminating signed chain hash)."""
        raise NotImplementedError


class BufferAndSignStrategy(StreamSigningStrategy):
    name = "buffer_and_sign"

    def __init__(self, server_crypto: ServerCryptoConfig, handshake_id: str, session_key: bytes):
        self._server_crypto = server_crypto
        self._handshake_id = handshake_id
        self._session_key = session_key
        self._ctx = stream_context(handshake_id)
        self._buffer = bytearray()

    def add_chunk(self, plaintext: bytes, index: int) -> dict | None:
        self._buffer.extend(plaintext)
        return None

    def finalize(self, n_chunks: int) -> dict | None:
        aead = aead_encrypt(self._session_key, bytes(self._buffer))
        signature, meta = self._server_crypto.sign(
            self._handshake_id, buffered_message(self._ctx, aead.nonce, aead.ciphertext))
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
        self._ctx = stream_context(handshake_id)

    def add_chunk(self, plaintext: bytes, index: int) -> dict | None:
        aead = aead_encrypt(self._session_key, plaintext)
        # binds role, session, and sequence position -- see module docstring
        signature, meta = self._server_crypto.sign(
            self._handshake_id, chunk_message(self._ctx, index, aead.nonce, aead.ciphertext))
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
        # Signed end-of-stream record: without it, dropping the tail of the
        # stream leaves every remaining chunk individually valid.
        signature, meta = self._server_crypto.sign(self._handshake_id, end_message(self._ctx, n_chunks))
        return {
            "kind": "final_per_chunk",
            "n_chunks": n_chunks,
            "signature": signature,
            "sign_ms": meta["sign_ms"],
            "signature_bytes": len(signature),
        }


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
        self._ctx = stream_context(handshake_id)
        self._checkpoint_interval = checkpoint_interval
        self._running_hash = genesis_hash(handshake_id)
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
            signature, meta = self._server_crypto.sign(
                self._handshake_id, checkpoint_message(self._ctx, index, self._running_hash))
            row["signature"] = signature
            row["sign_ms"] = meta["sign_ms"]
            row["signature_bytes"] = len(signature)
            self._since_checkpoint = 0
        return row

    def finalize(self, n_chunks: int) -> dict | None:
        # Always sign the final chain hash and length, regardless of the
        # checkpoint schedule, so the stream is verifiable end-to-end and a
        # truncated stream cannot reuse an earlier checkpoint as its ending.
        signature, meta = self._server_crypto.sign(
            self._handshake_id, final_chain_message(self._ctx, n_chunks, self._running_hash))
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
    """The client's own recomputation of the session's hash chain, compared
    against checkpoint and final signatures."""

    handshake_id: str
    running_hash: bytes = field(init=False)
    ctx: bytes = field(init=False)
    n_absorbed: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self.ctx = stream_context(self.handshake_id)
        self.running_hash = genesis_hash(self.handshake_id)

    def absorb(self, index: int, nonce: bytes, ciphertext: bytes) -> bytes:
        envelope = nonce + ciphertext
        self.running_hash = hashlib.sha256(self.running_hash + _index_bytes(index) + envelope).digest()
        self.n_absorbed += 1
        return self.running_hash


def _decrypt_into(result: dict, session_key: bytes, nonce: bytes, ciphertext: bytes) -> None:
    try:
        result["plaintext"] = aead_decrypt(session_key, nonce, ciphertext)
        result["aead_ok"] = True
    except AEADError:
        result["aead_ok"] = False


def verify_buffer_and_sign_final(final_chunk: dict, session_key: bytes, sig_public_key: bytes,
                                  client_crypto: ClientCryptoConfig, handshake_id: str) -> dict:
    msg = buffered_message(stream_context(handshake_id), final_chunk["nonce"], final_chunk["ciphertext"])
    valid, meta = client_crypto.verify(msg, final_chunk["signature"], sig_public_key)
    result = {"signature_valid": valid, "verify_ms": meta["verify_ms"], "aead_ok": None, "plaintext": None}
    if valid:
        _decrypt_into(result, session_key, final_chunk["nonce"], final_chunk["ciphertext"])
    return result


def verify_per_chunk(chunk: dict, expected_index: int, session_key: bytes, sig_public_key: bytes,
                      client_crypto: ClientCryptoConfig, handshake_id: str) -> dict:
    msg = chunk_message(stream_context(handshake_id), chunk["index"], chunk["nonce"], chunk["ciphertext"])
    valid, meta = client_crypto.verify(msg, chunk["signature"], sig_public_key)
    result = {
        "index": chunk["index"],
        "signature_valid": valid,
        "verify_ms": meta["verify_ms"],
        "in_order": chunk["index"] == expected_index,
        "aead_ok": None,
        "plaintext": None,
    }
    if valid:
        _decrypt_into(result, session_key, chunk["nonce"], chunk["ciphertext"])
    return result


def verify_per_chunk_final(final_record: dict, n_received: int, sig_public_key: bytes,
                            client_crypto: ClientCryptoConfig, handshake_id: str) -> dict:
    """The signed end record must verify AND match the number of chunks the
    client actually accepted; otherwise chunks were dropped or appended."""
    msg = end_message(stream_context(handshake_id), final_record["n_chunks"])
    valid, meta = client_crypto.verify(msg, final_record["signature"], sig_public_key)
    count_ok = final_record["n_chunks"] == n_received
    return {"signature_valid": valid, "count_matches": count_ok, "verify_ms": meta["verify_ms"],
            "stream_fully_verified": valid and count_ok}


def verify_hash_chain_chunk(chunk: dict, chain_state: HashChainClientState, session_key: bytes,
                            sig_public_key: bytes | None = None,
                            client_crypto: ClientCryptoConfig | None = None) -> dict:
    """Absorbs one chunk into the client's chain and decrypts it. If the chunk
    carries a checkpoint signature (HashChainStrategy with checkpoint_interval)
    and a verification key is supplied, the signature is checked against the
    client's OWN running hash -- so a dropped, reordered, replayed, or altered
    chunk anywhere before this checkpoint makes it fail here, mid-stream,
    instead of only at the terminal signature."""
    expected_hash = chain_state.absorb(chunk["index"], chunk["nonce"], chunk["ciphertext"])
    result = {
        "index": chunk["index"],
        "chain_ok_so_far": expected_hash == chunk["chain_hash"],
        "aead_ok": None,
        "plaintext": None,
        "checkpoint": False,
        "checkpoint_valid": None,
        "verify_ms": 0.0,
    }
    if chunk.get("signature") and sig_public_key is not None and client_crypto is not None:
        msg = checkpoint_message(chain_state.ctx, chunk["index"], expected_hash)
        valid, meta = client_crypto.verify(msg, chunk["signature"], sig_public_key)
        result.update(checkpoint=True, checkpoint_valid=valid, verify_ms=meta["verify_ms"])
    _decrypt_into(result, session_key, chunk["nonce"], chunk["ciphertext"])
    return result


def verify_hash_chain_final(final_chunk: dict, chain_state: HashChainClientState, sig_public_key: bytes,
                             client_crypto: ClientCryptoConfig) -> dict:
    """Verifies the terminal signature over the client's own chain hash and
    chunk count -- the length is bound, so truncation cannot pass."""
    chain_matches = final_chunk["final_chain_hash"] == chain_state.running_hash
    count_ok = final_chunk["n_chunks"] == chain_state.n_absorbed
    msg = final_chain_message(chain_state.ctx, chain_state.n_absorbed, chain_state.running_hash)
    valid, meta = client_crypto.verify(msg, final_chunk["signature"], sig_public_key)
    return {
        "chain_matches_client_computed": chain_matches,
        "count_matches": count_ok,
        "signature_valid": valid,
        "verify_ms": meta["verify_ms"],
        "stream_fully_verified": chain_matches and count_ok and valid,
    }
