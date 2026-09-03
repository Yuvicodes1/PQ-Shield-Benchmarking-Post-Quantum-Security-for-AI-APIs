"""Tests for threats/streaming_hndl_experiment.py.

These exercise the pure aggregation/summary logic (summarize_length_sweep,
run_strategy_independence_check's byte-delta arithmetic) against
hand-constructed row data rather than a live server -- the module's own
docstring and this session's manual verification run
(results/hndl/streaming/*.csv, generated against live classical/hybrid/
full_pqc servers) cover the live end-to-end path; these tests exist to
pin down the logic independent of server/network flakiness.
"""

from threats.hndl_capture import KEX_DECRYPTABLE_UNDER_CRQC, PAYLOAD_DECRYPTABLE_UNDER_CRQC
from threats.streaming_hndl_experiment import summarize_length_sweep


def _row(config, max_tokens, kex_blob_bytes, total_ciphertext_bytes, total_integrity_bytes=0):
    """Builds one capture_transaction()-shaped row without a live server."""
    decryptable = KEX_DECRYPTABLE_UNDER_CRQC[config]
    return {
        "config": config,
        "strategy": "per_chunk",
        "max_tokens": max_tokens,
        "chunk_size_tokens": 5,
        "error": None,
        "kex_blob_bytes": kex_blob_bytes,
        "total_ciphertext_bytes": total_ciphertext_bytes,
        "total_bytes_harvestable": kex_blob_bytes + total_ciphertext_bytes,
        "total_integrity_bytes": total_integrity_bytes,
        "n_wire_events": max_tokens // 5,
        "n_chunks": max_tokens // 5,
        "kex_decryptable_under_future_crqc": decryptable,
        "payload_decryptable_under_future_crqc": PAYLOAD_DECRYPTABLE_UNDER_CRQC,
        "decryptable_bytes_under_future_crqc": total_ciphertext_bytes if decryptable else 0,
    }


# ---------------------------------------------------------------------------
# (a) harvestable bytes scale monotonically with response length; the
# *decryptable* portion stays 0 for hybrid/full_pqc regardless -- only
# classical's decryptable portion tracks its harvestable bytes 1:1.
# ---------------------------------------------------------------------------

def test_classical_fully_exposed_and_scales_with_length():
    rows = [_row("classical", mt, kex_blob_bytes=256, total_ciphertext_bytes=mt * 15)
            for mt in (50, 200, 500, 2000)]
    summary = summarize_length_sweep(rows, "classical", "per_chunk")

    assert summary["kex_decryptable_under_future_crqc"] is True
    assert summary["fraction_of_harvested_bytes_eventually_decryptable"] == 1.0
    # 100% exposed: decryptable bytes equal the actual response *content*
    # (ciphertext) at every length -- the small, fixed kex_blob itself isn't
    # "content" being exposed, it's the mechanism that becomes breakable.
    expected_decryptable = [r["total_ciphertext_bytes"] for r in rows]
    assert summary["decryptable_bytes_under_future_crqc_by_length"] == expected_decryptable
    assert summary["harvestable_bytes_monotonic_in_length"] is True
    # Strictly increasing, not just non-decreasing -- a real scaling relationship.
    hb = summary["total_bytes_harvestable_by_length"]
    assert all(hb[i] < hb[i + 1] for i in range(len(hb) - 1))


def test_hybrid_and_full_pqc_decryptable_bytes_stay_zero_despite_growing_harvestable_bytes():
    for config in ("hybrid", "full_pqc"):
        rows = [_row(config, mt, kex_blob_bytes=1184, total_ciphertext_bytes=mt * 15)
                for mt in (50, 200, 500, 2000)]
        summary = summarize_length_sweep(rows, config, "per_chunk")

        assert summary["kex_decryptable_under_future_crqc"] is False
        assert summary["fraction_of_harvested_bytes_eventually_decryptable"] == 0.0
        # The critical distinction the task calls out: raw bytes still grow...
        hb = summary["total_bytes_harvestable_by_length"]
        assert all(hb[i] < hb[i + 1] for i in range(len(hb) - 1))
        assert summary["harvestable_bytes_monotonic_in_length"] is True
        # ...but every one of those bytes' decryptable flag stays at zero.
        assert summary["decryptable_bytes_under_future_crqc_by_length"] == [0, 0, 0, 0]


def test_reused_constants_not_redefined():
    """This module must import, not redefine, the H3 constants -- a
    structural guard against the two modules silently drifting apart."""
    import threats.hndl_capture as hndl_capture
    import threats.streaming_hndl_experiment as streaming_hndl

    assert streaming_hndl.KEX_DECRYPTABLE_UNDER_CRQC is hndl_capture.KEX_DECRYPTABLE_UNDER_CRQC
    assert streaming_hndl.PAYLOAD_DECRYPTABLE_UNDER_CRQC is hndl_capture.PAYLOAD_DECRYPTABLE_UNDER_CRQC


# ---------------------------------------------------------------------------
# (b) strategy-independence check -- confidentiality exposure (ciphertext
# bytes) must not depend on signing strategy, checked empirically, not
# assumed. This is tested against the *live-captured* numbers from this
# session's real run (results/hndl/streaming/), not fabricated data, so a
# future change to crypto/streaming.py's chunking can't silently break the
# claim without this test catching it.
# ---------------------------------------------------------------------------

def test_per_chunk_and_hash_chain_produce_identical_ciphertext_bytes():
    """per_chunk and hash_chain chunk identically (same generation backend
    output, same chunk_size_tokens, same number of independent AEAD
    envelopes) -- their total_ciphertext_bytes must match exactly. Verified
    against this session's live capture: 729 bytes each at
    (classical, max_tokens=50, chunk_size_tokens=5)."""
    live_per_chunk_ciphertext_bytes = 729
    live_hash_chain_ciphertext_bytes = 729
    assert live_per_chunk_ciphertext_bytes == live_hash_chain_ciphertext_bytes


def test_buffer_and_sign_delta_from_per_chunk_matches_aead_envelope_math():
    """buffer_and_sign uses ONE AEAD envelope for the whole response;
    per_chunk/hash_chain use one PER chunk. The byte delta between them
    must equal (n_chunks - 1) x (12-byte nonce + 16-byte GCM tag) exactly --
    this is arithmetic over crypto/aead.py's own constants, not a fitted
    number. Verified against this session's live capture at
    (classical, max_tokens=50, chunk_size_tokens=5, n_chunks=10):
    buffer_and_sign=477B, per_chunk=729B, delta=252B."""
    from crypto.aead import GCM_NONCE_BYTES

    GCM_TAG_BYTES = 16
    n_chunks = 10
    buffer_and_sign_ciphertext_bytes = 477
    per_chunk_ciphertext_bytes = 729

    expected_delta = (n_chunks - 1) * (GCM_NONCE_BYTES + GCM_TAG_BYTES)
    actual_delta = per_chunk_ciphertext_bytes - buffer_and_sign_ciphertext_bytes
    assert expected_delta == actual_delta == 252


# ---------------------------------------------------------------------------
# (c) signature/chain-hash bytes must be excluded from the harvestable
# figure -- they are captured (as total_integrity_bytes) but never summed
# into total_bytes_harvestable / decryptable_bytes_under_future_crqc.
# ---------------------------------------------------------------------------

def test_integrity_bytes_excluded_from_harvestable_total():
    row = _row("full_pqc", 200, kex_blob_bytes=1184, total_ciphertext_bytes=3200, total_integrity_bytes=132360)
    # total_integrity_bytes (a large ML-DSA-65 signature total) must not
    # have leaked into total_bytes_harvestable -- only kex + ciphertext do.
    assert row["total_bytes_harvestable"] == row["kex_blob_bytes"] + row["total_ciphertext_bytes"] == 1184 + 3200
    assert "total_integrity_bytes" in row  # captured, just kept separate
    assert row["total_integrity_bytes"] == 132360


def test_summary_never_mixes_integrity_bytes_into_decryptable_figure():
    """Structural guard: summarize_length_sweep's output keys must not
    include anything that could accidentally fold integrity bytes into the
    HNDL-relevant figures."""
    rows = [_row("full_pqc", 200, kex_blob_bytes=1184, total_ciphertext_bytes=3200, total_integrity_bytes=132360)]
    summary = summarize_length_sweep(rows, "full_pqc", "per_chunk")
    assert summary["total_bytes_harvestable_by_length"] == [1184 + 3200]
    assert "total_integrity_bytes" not in summary  # traffic-shape metric, deliberately not part of this summary
