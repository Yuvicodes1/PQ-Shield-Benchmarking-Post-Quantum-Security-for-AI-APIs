"""Tests for crypto/streaming.py -- the three streaming signing strategies.

Beyond plain round-trips, these specifically test the failure modes that
matter for a streaming protocol and that a single-shot (non-streaming)
protocol never has to consider: a tampered middle chunk, a reordered chunk,
and a dropped chunk. See crypto/streaming.py's module docstring for why
PER_CHUNK binds the index into what is signed, and why HASH_CHAIN does not
need to.
"""

import pytest

from crypto.registry import CONFIG_NAMES, get_client_crypto, get_server_crypto
from crypto.streaming import (
    HashChainClientState,
    get_server_strategy,
    verify_buffer_and_sign_final,
    verify_hash_chain_chunk,
    verify_hash_chain_final,
    verify_per_chunk,
)

CHUNKS = [b"The quick ", b"brown fox ", b"jumps over ", b"the lazy dog."]


def _handshake(config_name: str):
    server = get_server_crypto(config_name)
    client = get_client_crypto(config_name)
    bundle = server.new_handshake()
    est = client.establish(bundle.kex_public_key)
    session_key, _ = server.accept(bundle.handshake_id, est.kex_blob)
    assert session_key == est.session_key
    return server, client, bundle, session_key


@pytest.mark.parametrize("config_name", CONFIG_NAMES)
def test_buffer_and_sign_roundtrip(config_name):
    server, client, bundle, session_key = _handshake(config_name)
    strategy = get_server_strategy("buffer_and_sign", server, bundle.handshake_id, session_key)

    for i, chunk in enumerate(CHUNKS):
        assert strategy.add_chunk(chunk, i) is None  # withholds until finalize

    final = strategy.finalize(len(CHUNKS))
    result = verify_buffer_and_sign_final(final, session_key, bundle.sig_public_key, client)

    assert result["signature_valid"] is True
    assert result["aead_ok"] is True
    assert result["plaintext"] == b"".join(CHUNKS)


@pytest.mark.parametrize("config_name", CONFIG_NAMES)
def test_buffer_and_sign_tampered_ciphertext_rejected(config_name):
    server, client, bundle, session_key = _handshake(config_name)
    strategy = get_server_strategy("buffer_and_sign", server, bundle.handshake_id, session_key)
    for i, chunk in enumerate(CHUNKS):
        strategy.add_chunk(chunk, i)
    final = strategy.finalize(len(CHUNKS))

    tampered = bytearray(final["ciphertext"])
    tampered[0] ^= 0xFF
    final["ciphertext"] = bytes(tampered)

    result = verify_buffer_and_sign_final(final, session_key, bundle.sig_public_key, client)
    # Signature covers (nonce||ciphertext), so tampering the ciphertext must
    # also break the signature check -- the envelope no longer matches.
    assert result["signature_valid"] is False


@pytest.mark.parametrize("config_name", CONFIG_NAMES)
def test_per_chunk_roundtrip_all_chunks_valid(config_name):
    server, client, bundle, session_key = _handshake(config_name)
    strategy = get_server_strategy("per_chunk", server, bundle.handshake_id, session_key)

    wire_chunks = [strategy.add_chunk(c, i) for i, c in enumerate(CHUNKS)]
    assert strategy.finalize(len(CHUNKS)) is None  # nothing withheld

    reconstructed = b""
    for i, chunk in enumerate(wire_chunks):
        result = verify_per_chunk(chunk, expected_index=i, session_key=session_key,
                                   sig_public_key=bundle.sig_public_key, client_crypto=client)
        assert result["signature_valid"] is True
        assert result["aead_ok"] is True
        assert result["in_order"] is True
        reconstructed += result["plaintext"]

    assert reconstructed == b"".join(CHUNKS)


@pytest.mark.parametrize("config_name", CONFIG_NAMES)
def test_per_chunk_tampering_one_chunk_does_not_affect_others(config_name):
    """The key advantage PER_CHUNK claims over buffer_and_sign: a corrupted
    chunk is caught immediately and in isolation -- the rest of the stream
    remains independently verifiable."""
    server, client, bundle, session_key = _handshake(config_name)
    strategy = get_server_strategy("per_chunk", server, bundle.handshake_id, session_key)
    wire_chunks = [strategy.add_chunk(c, i) for i, c in enumerate(CHUNKS)]

    tampered = bytearray(wire_chunks[2]["ciphertext"])
    tampered[0] ^= 0xFF
    wire_chunks[2]["ciphertext"] = bytes(tampered)

    results = [
        verify_per_chunk(c, expected_index=i, session_key=session_key,
                          sig_public_key=bundle.sig_public_key, client_crypto=client)
        for i, c in enumerate(wire_chunks)
    ]

    assert results[0]["signature_valid"] is True
    assert results[1]["signature_valid"] is True
    assert results[2]["signature_valid"] is False  # only the tampered chunk fails
    assert results[3]["signature_valid"] is True


@pytest.mark.parametrize("config_name", CONFIG_NAMES)
def test_per_chunk_detects_reordering(config_name):
    """A naive per-chunk scheme that signs only (nonce||ciphertext) would let
    an adversary swap two independently-valid signed chunks undetected.
    Binding the index into the signed bytes plus a client-side sequence
    check closes that: swapped chunks either fail the sequence check (index
    values arrive out of order) even though each one's own signature is
    still individually valid."""
    server, client, bundle, session_key = _handshake(config_name)
    strategy = get_server_strategy("per_chunk", server, bundle.handshake_id, session_key)
    wire_chunks = [strategy.add_chunk(c, i) for i, c in enumerate(CHUNKS)]

    # Swap chunks 1 and 2 in transit, without modifying their contents --
    # simulates a MITM reordering already-valid signed messages.
    reordered = list(wire_chunks)
    reordered[1], reordered[2] = reordered[2], reordered[1]

    results = [
        verify_per_chunk(c, expected_index=i, session_key=session_key,
                          sig_public_key=bundle.sig_public_key, client_crypto=client)
        for i, c in enumerate(reordered)
    ]

    # Each individual signature is still valid (the bytes themselves were not touched)...
    assert all(r["signature_valid"] for r in results)
    # ...but the sequence check catches the reordering the signature alone cannot.
    assert results[1]["in_order"] is False
    assert results[2]["in_order"] is False
    assert results[1]["index"] == 2  # slot 1 actually contains what was generated as index 2
    assert results[2]["index"] == 1


@pytest.mark.parametrize("config_name", CONFIG_NAMES)
def test_hash_chain_roundtrip(config_name):
    server, client, bundle, session_key = _handshake(config_name)
    strategy = get_server_strategy("hash_chain", server, bundle.handshake_id, session_key)

    wire_chunks = [strategy.add_chunk(c, i) for i, c in enumerate(CHUNKS)]
    final = strategy.finalize(len(CHUNKS))

    chain_state = HashChainClientState()
    reconstructed = b""
    for chunk in wire_chunks:
        result = verify_hash_chain_chunk(chunk, chain_state, session_key)
        assert result["chain_ok_so_far"] is True
        assert result["aead_ok"] is True
        reconstructed += result["plaintext"]

    final_result = verify_hash_chain_final(final, chain_state, bundle.sig_public_key, client)
    assert final_result["chain_matches_client_computed"] is True
    assert final_result["signature_valid"] is True
    assert final_result["stream_fully_verified"] is True
    assert reconstructed == b"".join(CHUNKS)


@pytest.mark.parametrize("config_name", CONFIG_NAMES)
def test_hash_chain_detects_tampered_middle_chunk(config_name):
    server, client, bundle, session_key = _handshake(config_name)
    strategy = get_server_strategy("hash_chain", server, bundle.handshake_id, session_key)
    wire_chunks = [strategy.add_chunk(c, i) for i, c in enumerate(CHUNKS)]
    final = strategy.finalize(len(CHUNKS))

    tampered = bytearray(wire_chunks[1]["ciphertext"])
    tampered[0] ^= 0xFF
    wire_chunks[1]["ciphertext"] = bytes(tampered)

    chain_state = HashChainClientState()
    chunk_results = [verify_hash_chain_chunk(c, chain_state, session_key) for c in wire_chunks]

    # AEAD catches the tampered chunk immediately, at the moment it arrives...
    assert chunk_results[1]["aead_ok"] is False
    # ...and because every later hash folds in this one, the chain the client
    # recomputes no longer matches what the server originally signed.
    final_result = verify_hash_chain_final(final, chain_state, bundle.sig_public_key, client)
    assert final_result["chain_matches_client_computed"] is False
    assert final_result["stream_fully_verified"] is False


@pytest.mark.parametrize("config_name", CONFIG_NAMES)
def test_hash_chain_detects_dropped_chunk(config_name):
    """A chunk silently removed in transit (not tampered, just missing) is
    exactly the failure mode independent per-chunk signatures do not catch
    on their own (each remaining chunk is still individually valid) but the
    hash chain does, because the dropped chunk's hash contribution is
    permanently missing from every subsequent link."""
    server, client, bundle, session_key = _handshake(config_name)
    strategy = get_server_strategy("hash_chain", server, bundle.handshake_id, session_key)
    wire_chunks = [strategy.add_chunk(c, i) for i, c in enumerate(CHUNKS)]
    final = strategy.finalize(len(CHUNKS))

    chain_state = HashChainClientState()
    surviving_chunks = [wire_chunks[0], wire_chunks[2], wire_chunks[3]]  # chunk 1 dropped
    for c in surviving_chunks:
        verify_hash_chain_chunk(c, chain_state, session_key)

    final_result = verify_hash_chain_final(final, chain_state, bundle.sig_public_key, client)
    assert final_result["chain_matches_client_computed"] is False
    assert final_result["stream_fully_verified"] is False


@pytest.mark.parametrize("config_name", CONFIG_NAMES)
def test_hash_chain_checkpoint_interval_produces_intermediate_signatures(config_name):
    server, client, bundle, session_key = _handshake(config_name)
    strategy = get_server_strategy(
        "hash_chain", server, bundle.handshake_id, session_key, checkpoint_interval=2
    )
    wire_chunks = [strategy.add_chunk(c, i) for i, c in enumerate(CHUNKS)]
    strategy.finalize(len(CHUNKS))

    # With checkpoint_interval=2 and 4 chunks, chunks at index 1 and 3
    # (the 2nd and 4th chunk) should carry a checkpoint signature.
    assert wire_chunks[0]["signature"] is None
    assert wire_chunks[1]["signature"] is not None
    assert wire_chunks[2]["signature"] is None
    assert wire_chunks[3]["signature"] is not None


def test_signature_byte_cost_ordering_matches_design_expectation():
    """Sanity check on the core motivating claim: for the same content,
    per_chunk costs strictly more signature bytes than hash_chain (default,
    no checkpoints) or buffer_and_sign, which cost exactly one signature."""
    server, client, bundle, session_key = _handshake("full_pqc")

    buf = get_server_strategy("buffer_and_sign", server, bundle.handshake_id, session_key)
    for i, c in enumerate(CHUNKS):
        buf.add_chunk(c, i)
    buf_final = buf.finalize(len(CHUNKS))
    buf_total_sig_bytes = buf_final["signature_bytes"]

    server2, _, bundle2, session_key2 = _handshake("full_pqc")
    per_chunk = get_server_strategy("per_chunk", server2, bundle2.handshake_id, session_key2)
    per_chunk_total_sig_bytes = sum(
        per_chunk.add_chunk(c, i)["signature_bytes"] for i, c in enumerate(CHUNKS)
    )

    server3, _, bundle3, session_key3 = _handshake("full_pqc")
    chain = get_server_strategy("hash_chain", server3, bundle3.handshake_id, session_key3)
    for i, c in enumerate(CHUNKS):
        chain.add_chunk(c, i)
    chain_final = chain.finalize(len(CHUNKS))
    chain_total_sig_bytes = chain_final["signature_bytes"]

    assert chain_total_sig_bytes == buf_total_sig_bytes  # both: exactly one signature
    assert per_chunk_total_sig_bytes == len(CHUNKS) * buf_total_sig_bytes
    assert per_chunk_total_sig_bytes > buf_total_sig_bytes
