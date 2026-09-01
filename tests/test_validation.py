"""Tests for validation/ -- the external-ground-truth layer.

These are deliberately assertions about *published standards*, not about
PQ-Shield's own prior output, so they cannot drift along with the
implementation. If liboqs is upgraded and a parameter size changes, or if the
ctypes binding is broken, these fail loudly.

The ordering tests use a small iteration count so the suite stays fast; they
check direction (A faster than B), never absolute timings, so they are stable
across hardware and CI runners.
"""

import pytest

from validation.primitive_bench import bench_classical, bench_ml_dsa_65, bench_ml_kem_768, check_orderings
from validation.reference_data import FIPS_203_ML_KEM_768, FIPS_204_ML_DSA_65, ROUND3_DILITHIUM3_SUPERSEDED
from validation.spec_conformance import check_ml_dsa_65, check_ml_kem_768, check_standard_version_drift


def test_ml_kem_768_matches_fips_203():
    for check in check_ml_kem_768():
        assert check["conformant"], f"FIPS 203 conformance failure: {check['parameter']}"


def test_ml_dsa_65_matches_fips_204():
    for check in check_ml_dsa_65():
        assert check["conformant"], f"FIPS 204 conformance failure: {check['parameter']}"


def test_tracks_fips_204_final_not_superseded_round3():
    """ML-DSA-65 must match FIPS 204 as finalised (4032 B secret key, 3309 B
    signature), not the pre-standardisation Round 3 Dilithium3 values (4000 B,
    3293 B) that several post-2024 publications still cite."""
    drift = check_standard_version_drift()
    assert drift["matches_fips_204_final"], drift
    assert not drift["matches_superseded_round3"], drift


def test_reference_constants_are_internally_distinct():
    """Guards against someone 'fixing' the reference table by making the
    superseded values equal the final ones, which would silently disable
    test_tracks_fips_204_final_not_superseded_round3."""
    assert FIPS_204_ML_DSA_65.signature_bytes != ROUND3_DILITHIUM3_SUPERSEDED.signature_bytes
    assert FIPS_204_ML_DSA_65.secret_key_bytes != ROUND3_DILITHIUM3_SUPERSEDED.secret_key_bytes
    assert FIPS_203_ML_KEM_768.ciphertext_bytes == 1088


@pytest.fixture(scope="module")
def orderings():
    n = 40  # small but enough for a stable direction check
    kem = bench_ml_kem_768(n)
    sig = bench_ml_dsa_65(n)
    classical = bench_classical(n, keygen_iterations=3)
    return check_orderings(kem, sig, classical)


def test_ml_dsa_verify_faster_than_sign(orderings):
    """Fiat-Shamir with Aborts: signing does rejection sampling, verification
    is single-pass. Verification must be the cheaper operation."""
    check = orderings[0]
    assert check["holds"], check["evidence"]


def test_ml_kem_keygen_faster_than_rsa_keygen(orderings):
    """The mechanism behind PQ-Shield's high-concurrency availability finding:
    RSA key generation is probabilistic prime search, ML-KEM key generation is
    not. This gap should be large on any hardware."""
    check = orderings[1]
    assert check["holds"], check["evidence"]
    assert check["evidence"]["speedup_factor"] > 10, (
        "Expected ML-KEM keygen to be at least an order of magnitude faster than "
        f"RSA-2048 keygen; got {check['evidence']['speedup_factor']:.1f}x"
    )


def test_h4_mldsa_verify_not_slower_than_ecdsa(orderings):
    """PQ-Shield's H4, checked at the primitive level so the application-level
    result has independent corroboration on the same host."""
    check = orderings[2]
    assert check["holds"], check["evidence"]
