"""Tests for analysis/streaming_model_validation.py's prediction functions,
against hand-computed values -- independent of any CSV data on disk, so
these stay meaningful even if results/streaming/*.csv changes or is absent.

See analysis/streaming_model_validation.py's module docstring for why an
analytical model is the correct substitute for an external streaming
benchmark, and for why ML-DSA-65 gets exact byte predictions while
ECDSA-P256 only gets a range.
"""

import pytest

from analysis.streaming_model_validation import (
    ECDSA_P256_DER_MAX_BYTES,
    ECDSA_P256_DER_MIN_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
    cold_start_ms_and_tolerance,
    expected_signature_bytes,
    expected_signature_count,
    sig_algorithm_for_config,
    validate_row,
)


# ---------------------------------------------------------------------------
# expected_signature_count -- the four strategy/checkpoint combinations from
# the task's own table, by hand:
#   buffer_and_sign               -> 1
#   per_chunk                     -> n_chunks
#   hash_chain, no checkpoints    -> 1
#   hash_chain, checkpoint every k -> floor(n_chunks / k) + 1
# ---------------------------------------------------------------------------

def test_buffer_and_sign_always_one_signature():
    # buffer_and_sign's n_chunks is always 0 in practice (see module
    # docstring) but the model must not depend on that -- 1 regardless.
    assert expected_signature_count("buffer_and_sign", n_chunks=0, checkpoint_interval=None) == 1
    assert expected_signature_count("buffer_and_sign", n_chunks=95, checkpoint_interval=None) == 1


def test_per_chunk_one_signature_per_chunk():
    assert expected_signature_count("per_chunk", n_chunks=100, checkpoint_interval=None) == 100
    assert expected_signature_count("per_chunk", n_chunks=1, checkpoint_interval=None) == 1
    assert expected_signature_count("per_chunk", n_chunks=0, checkpoint_interval=None) == 0


def test_hash_chain_no_checkpoint_is_one_signature():
    assert expected_signature_count("hash_chain", n_chunks=95, checkpoint_interval=None) == 1
    assert expected_signature_count("hash_chain", n_chunks=95, checkpoint_interval=0) == 1


@pytest.mark.parametrize("n_chunks,k,expected", [
    (95, 10, 10),   # floor(95/10) + 1 = 9 + 1 = 10
    (100, 10, 11),  # floor(100/10) + 1 = 10 + 1 = 11 (evenly divides, still +1 for the final signature)
    (100, 25, 5),   # floor(100/25) + 1 = 4 + 1 = 5
    (5, 100, 1),    # fewer chunks than the checkpoint interval -> just the final signature
])
def test_hash_chain_with_checkpoint_matches_hand_computed(n_chunks, k, expected):
    assert expected_signature_count("hash_chain", n_chunks=n_chunks, checkpoint_interval=k) == expected


def test_hash_chain_and_per_chunk_are_not_conflated_at_equal_n_chunks():
    """The exact failure mode the task calls out: checkpointed hash_chain and
    per_chunk must not collapse to the same prediction just because they
    share an n_chunks value."""
    n_chunks = 40
    assert expected_signature_count("per_chunk", n_chunks, checkpoint_interval=None) == 40
    assert expected_signature_count("hash_chain", n_chunks, checkpoint_interval=None) == 1
    assert expected_signature_count("hash_chain", n_chunks, checkpoint_interval=10) == 5


def test_unknown_strategy_raises():
    with pytest.raises(ValueError):
        expected_signature_count("not_a_real_strategy", n_chunks=10, checkpoint_interval=None)


# ---------------------------------------------------------------------------
# expected_signature_bytes -- exact for ML-DSA-65, a range for ECDSA-P256
# ---------------------------------------------------------------------------

def test_ml_dsa_65_bytes_are_exact_not_a_range():
    lo, hi = expected_signature_bytes("ML-DSA-65", n_signatures=1)
    assert lo == hi == ML_DSA_65_SIGNATURE_BYTES == 3309

    lo, hi = expected_signature_bytes("ML-DSA-65", n_signatures=100)
    assert lo == hi == 330900


def test_ecdsa_p256_bytes_are_a_genuine_range():
    lo, hi = expected_signature_bytes("ECDSA-P256-SHA256", n_signatures=1)
    assert (lo, hi) == (ECDSA_P256_DER_MIN_BYTES, ECDSA_P256_DER_MAX_BYTES) == (70, 72)
    assert lo < hi  # not degenerately exact -- this is the point of the range

    lo, hi = expected_signature_bytes("ECDSA-P256-SHA256", n_signatures=100)
    assert (lo, hi) == (7000, 7200)


def test_zero_signatures_is_zero_bytes():
    assert expected_signature_bytes("ML-DSA-65", n_signatures=0) == (0, 0)
    assert expected_signature_bytes("ECDSA-P256-SHA256", n_signatures=0) == (0, 0)


def test_unknown_algorithm_raises():
    with pytest.raises(ValueError):
        expected_signature_bytes("RSA-4096", n_signatures=1)


# ---------------------------------------------------------------------------
# sig_algorithm_for_config -- must come from crypto/registry.py, not a
# hardcoded per-strategy table (the task's explicit correctness requirement)
# ---------------------------------------------------------------------------

def test_sig_algorithm_looked_up_per_config():
    assert sig_algorithm_for_config("classical") == "ECDSA-P256-SHA256"
    assert sig_algorithm_for_config("hybrid") == "ECDSA-P256-SHA256"
    assert sig_algorithm_for_config("full_pqc") == "ML-DSA-65"


# ---------------------------------------------------------------------------
# Hand-computed end-to-end byte predictions for each row of the table in the
# task/module docstring, without touching any CSV.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("config,strategy,n_chunks,checkpoint_interval,expected_bytes_range", [
    ("full_pqc", "buffer_and_sign", 0, None, (3309, 3309)),
    ("full_pqc", "per_chunk", 100, None, (330900, 330900)),
    ("full_pqc", "hash_chain", 95, None, (3309, 3309)),
    ("full_pqc", "hash_chain", 100, 10, (11 * 3309, 11 * 3309)),
    ("classical", "buffer_and_sign", 0, None, (70, 72)),
    ("classical", "per_chunk", 100, None, (7000, 7200)),
    ("classical", "hash_chain", 95, None, (70, 72)),
    ("hybrid", "hash_chain", 100, 25, (5 * 70, 5 * 72)),
])
def test_full_prediction_pipeline_matches_hand_computed(
    config, strategy, n_chunks, checkpoint_interval, expected_bytes_range
):
    n_sigs = expected_signature_count(strategy, n_chunks, checkpoint_interval)
    sig_algorithm = sig_algorithm_for_config(config)
    lo, hi = expected_signature_bytes(sig_algorithm, n_sigs)
    assert (lo, hi) == expected_bytes_range


# ---------------------------------------------------------------------------
# Cold-start timing baseline: applies only to buffer_and_sign, only when
# primitive_bench.json has a "cold_start_signing" section (older files
# without it must degrade gracefully, not crash). See
# analysis/streaming_model_validation.py's cold_start_ms_and_tolerance()
# docstring and docs/STREAMING.md's "Validating the measurement instrument
# itself" for why this baseline exists and what it fixes.
# ---------------------------------------------------------------------------

_FAKE_PRIMITIVE_BENCH_WITH_COLD_START = {
    "classical": {"ecdsa_p256_sign": {"mean_us": 30.0, "median_us": 28.0, "p99_us": 44.0}},
    "ml_dsa_65": {"sign": {"mean_us": 120.0, "median_us": 105.0, "p99_us": 316.0}},
    "cold_start_signing": {
        "ecdsa_p256_sign": {"mean_ms": 8.0, "median_ms": 7.9, "min_ms": 7.8, "max_ms": 8.2},
        "ml_dsa_65_sign": {"mean_ms": 0.15, "median_ms": 0.14, "min_ms": 0.12, "max_ms": 0.20},
    },
}

_FAKE_PRIMITIVE_BENCH_WITHOUT_COLD_START = {
    "classical": {"ecdsa_p256_sign": {"mean_us": 30.0, "median_us": 28.0, "p99_us": 44.0}},
    "ml_dsa_65": {"sign": {"mean_us": 120.0, "median_us": 105.0, "p99_us": 316.0}},
}


def test_cold_start_lookup_returns_none_when_section_absent():
    """Older primitive_bench.json files (predating bench_cold_start_signing())
    must not crash the validator -- they simply don't get the correction."""
    assert cold_start_ms_and_tolerance("ECDSA-P256-SHA256", _FAKE_PRIMITIVE_BENCH_WITHOUT_COLD_START) is None


def test_cold_start_lookup_returns_mean_and_tolerance_when_present():
    mean_ms, tolerance = cold_start_ms_and_tolerance("ECDSA-P256-SHA256", _FAKE_PRIMITIVE_BENCH_WITH_COLD_START)
    assert mean_ms == 8.0
    # max/mean = 8.2/8.0 = 1.025, below the 1.5 floor -- so the floor, not the
    # computed ratio, is what should come back here (see the dedicated floor
    # test below for the case where the computed ratio actually exceeds it).
    assert tolerance == 1.5


def test_cold_start_lookup_uses_computed_ratio_when_it_exceeds_the_floor():
    wide = {"cold_start_signing": {"ecdsa_p256_sign": {"mean_ms": 8.0, "max_ms": 16.0}}}
    mean_ms, tolerance = cold_start_ms_and_tolerance("ECDSA-P256-SHA256", wide)
    assert mean_ms == 8.0
    assert tolerance == pytest.approx(2.0)  # 16.0 / 8.0, not the 1.5 floor


def test_cold_start_tolerance_floors_at_1_5x():
    """A very tight max/mean spread (e.g. a lucky small sample) must not
    produce an unrealistically strict tolerance."""
    tight = {"cold_start_signing": {"ecdsa_p256_sign": {"mean_ms": 8.0, "max_ms": 8.001}}}
    mean_ms, tolerance = cold_start_ms_and_tolerance("ECDSA-P256-SHA256", tight)
    assert tolerance == 1.5


def test_validate_row_applies_cold_start_only_to_buffer_and_sign():
    """The cold-start correction must appear for buffer_and_sign and must
    NOT appear for per_chunk/hash_chain, even though all three could in
    principle use the same signature scheme -- applying it there would
    overclaim a mechanism only confirmed for buffer_and_sign (see the
    module docstring: it's typically the first ECDSA sign call a freshly
    started process performs, per bench/streaming_runner.py's default
    strategy order; per_chunk/hash_chain are not)."""
    base_row = {
        "config": "classical", "n_chunks": 0, "total_signature_bytes": 71, "total_signing_ms": 0.05,
    }

    buffer_row = validate_row({**base_row, "strategy": "buffer_and_sign"}, _FAKE_PRIMITIVE_BENCH_WITH_COLD_START)
    assert buffer_row["timing_ratio_cold_start"] is not None
    assert buffer_row["predicted_signing_ms_cold_start"] == pytest.approx(8.0)  # 1 signature x 8.0ms

    per_chunk_row = validate_row(
        {**base_row, "strategy": "per_chunk", "n_chunks": 10}, _FAKE_PRIMITIVE_BENCH_WITH_COLD_START
    )
    assert per_chunk_row["timing_ratio_cold_start"] is None
    assert per_chunk_row["timing_ok_cold_start"] is None

    hash_chain_row = validate_row(
        {**base_row, "strategy": "hash_chain", "n_chunks": 10}, _FAKE_PRIMITIVE_BENCH_WITH_COLD_START
    )
    assert hash_chain_row["timing_ratio_cold_start"] is None


def test_validate_row_cold_start_absent_when_primitive_bench_lacks_it():
    row = validate_row(
        {"config": "classical", "strategy": "buffer_and_sign", "n_chunks": 0,
         "total_signature_bytes": 71, "total_signing_ms": 0.05},
        _FAKE_PRIMITIVE_BENCH_WITHOUT_COLD_START,
    )
    assert row["timing_ratio_cold_start"] is None
    assert row["timing_ok_cold_start"] is None
