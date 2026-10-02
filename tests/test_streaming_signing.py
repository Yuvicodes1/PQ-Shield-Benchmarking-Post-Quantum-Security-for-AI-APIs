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
    verify_per_chunk_final,
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
    result = verify_buffer_and_sign_final(final, session_key, bundle.sig_public_key, client, bundle.handshake_id)

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

    result = verify_buffer_and_sign_final(final, session_key, bundle.sig_public_key, client, bundle.handshake_id)
    # Signature covers (nonce||ciphertext), so tampering the ciphertext must
    # also break the signature check -- the envelope no longer matches.
    assert result["signature_valid"] is False


@pytest.mark.parametrize("config_name", CONFIG_NAMES)
def test_per_chunk_roundtrip_all_chunks_valid(config_name):
    server, client, bundle, session_key = _handshake(config_name)
    strategy = get_server_strategy("per_chunk", server, bundle.handshake_id, session_key)

    wire_chunks = [strategy.add_chunk(c, i) for i, c in enumerate(CHUNKS)]
    end = strategy.finalize(len(CHUNKS))  # signed end-of-stream record, no withheld content
    assert end["kind"] == "final_per_chunk" and end["n_chunks"] == len(CHUNKS)
    assert verify_per_chunk_final(end, len(CHUNKS), bundle.sig_public_key, client,
                                  bundle.handshake_id)["stream_fully_verified"] is True

    reconstructed = b""
    for i, chunk in enumerate(wire_chunks):
        result = verify_per_chunk(chunk, expected_index=i, session_key=session_key,
                                   sig_public_key=bundle.sig_public_key, client_crypto=client, handshake_id=bundle.handshake_id)
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
                          sig_public_key=bundle.sig_public_key, client_crypto=client, handshake_id=bundle.handshake_id)
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
                          sig_public_key=bundle.sig_public_key, client_crypto=client, handshake_id=bundle.handshake_id)
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

    chain_state = HashChainClientState(bundle.handshake_id)
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

    chain_state = HashChainClientState(bundle.handshake_id)
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

    chain_state = HashChainClientState(bundle.handshake_id)
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


# --- v2: truncation, duplication, and cross-session replay ----------------------------------

@pytest.mark.parametrize("config_name", CONFIG_NAMES)
def test_per_chunk_end_record_detects_truncation(config_name):
    """Dropping the tail leaves every remaining chunk valid and in order; only
    the signed end record (count mismatch, or its absence) reveals it."""
    server, client, bundle, session_key = _handshake(config_name)
    strategy = get_server_strategy("per_chunk", server, bundle.handshake_id, session_key)
    wire = [strategy.add_chunk(c, i) for i, c in enumerate(CHUNKS)]
    end = strategy.finalize(len(CHUNKS))
    kept = wire[:2]
    assert all(verify_per_chunk(c, i, session_key, bundle.sig_public_key, client, bundle.handshake_id)
               ["signature_valid"] for i, c in enumerate(kept))
    r = verify_per_chunk_final(end, len(kept), bundle.sig_public_key, client, bundle.handshake_id)
    assert r["signature_valid"] is True and r["count_matches"] is False
    assert r["stream_fully_verified"] is False


@pytest.mark.parametrize("config_name", CONFIG_NAMES)
def test_hash_chain_final_binds_length(config_name):
    """A truncated chain cannot be completed with the original final record."""
    server, client, bundle, session_key = _handshake(config_name)
    strategy = get_server_strategy("hash_chain", server, bundle.handshake_id, session_key)
    wire = [strategy.add_chunk(c, i) for i, c in enumerate(CHUNKS)]
    final = strategy.finalize(len(CHUNKS))
    state = HashChainClientState(bundle.handshake_id)
    for c in wire[:2]:
        verify_hash_chain_chunk(c, state, session_key)
    assert verify_hash_chain_final(final, state, bundle.sig_public_key, client)["stream_fully_verified"] is False


@pytest.mark.parametrize("config_name", CONFIG_NAMES)
def test_per_chunk_detects_duplicate(config_name):
    server, client, bundle, session_key = _handshake(config_name)
    strategy = get_server_strategy("per_chunk", server, bundle.handshake_id, session_key)
    wire = [strategy.add_chunk(c, i) for i, c in enumerate(CHUNKS)]
    dup = wire[:2] + [wire[1]] + wire[2:]
    results = [verify_per_chunk(c, i, session_key, bundle.sig_public_key, client, bundle.handshake_id)
               for i, c in enumerate(dup)]
    assert results[2]["in_order"] is False


@pytest.mark.parametrize("config_name", ["classical_ecdhe", "hybrid", "full_pqc"])
def test_signatures_bound_to_session_even_with_same_signing_key(config_name):
    """Cross-session replay must fail even if the server reused one long-term
    signing key: a record signed under session A does not verify as session B."""
    server, client, bundle, session_key = _handshake(config_name)
    strategy = get_server_strategy("per_chunk", server, bundle.handshake_id, session_key)
    chunk = strategy.add_chunk(CHUNKS[0], 0)
    same_key = bundle.sig_public_key
    assert verify_per_chunk(chunk, 0, session_key, same_key, client, bundle.handshake_id)["signature_valid"]
    assert not verify_per_chunk(chunk, 0, session_key, same_key, client, "another-session")["signature_valid"]
    chain = get_server_strategy("hash_chain", server, bundle.handshake_id, session_key)
    wire = [chain.add_chunk(c, i) for i, c in enumerate(CHUNKS)]
    final = chain.finalize(len(CHUNKS))
    other = HashChainClientState("another-session")
    for c in wire:
        verify_hash_chain_chunk(c, other, session_key)
    assert verify_hash_chain_final(final, other, same_key, client)["stream_fully_verified"] is False
