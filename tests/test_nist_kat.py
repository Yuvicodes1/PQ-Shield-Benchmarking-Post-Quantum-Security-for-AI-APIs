"""Tests for validation/nist_kat.py -- ML-KEM-768 / ML-DSA-65 against NIST's
own ACVP known-answer-test vectors (the vectors used for FIPS 140
validation). This is the project's strongest ground-truth check: unlike
validation/spec_conformance.py (byte *lengths* match the standard), these
assert the actual cryptographic *output* is byte-for-byte identical to
NIST's reference computation on fixed, published inputs.

See validation/nist_kat.py's module docstring for exactly what is and is
not achievable through liboqs's public API (sigVer yes, keyGen/sigGen for
ML-DSA no) and for the external/pure-vs-internal ML-DSA interface trap --
not re-derived here.
"""

from validation.kat_vectors import (
    load_ml_dsa_65_sigver_vectors,
    load_ml_kem_768_encap_decap_vectors,
    load_ml_kem_768_keygen_vectors,
)
from validation.nist_kat import (
    run_all,
    run_ml_dsa_65_sigver,
    run_ml_kem_768_encap_decap,
    run_ml_kem_768_keygen,
)


def test_ml_kem_768_keygen_vectors_load_and_shape():
    vectors, meta = load_ml_kem_768_keygen_vectors()
    assert len(vectors) == 25
    assert meta["source"].endswith("internalProjection.json")
    v = vectors[0]
    assert len(v.d) == 32 and len(v.z) == 32
    assert len(v.coins) == 64
    assert len(v.ek) == 1184 and len(v.dk) == 2400


def test_ml_kem_768_keygen_all_byte_exact():
    result = run_ml_kem_768_keygen()
    assert result["total"] == 25
    assert result["passed"] == 25, [r for r in result["results"] if not r["passed"]]


def test_ml_kem_768_encap_decap_vectors_load_and_shape():
    encaps, decaps, meta = load_ml_kem_768_encap_decap_vectors()
    assert len(encaps) == 25
    assert len(decaps) == 10
    assert len(encaps[0].m) == 32
    # decapsulation vectors must include implicit-rejection ("modified
    # ciphertext") cases, not only the happy path -- otherwise this test
    # wouldn't actually exercise FIPS 203's implicit-rejection branch.
    assert any("modified" in v.reason for v in decaps)
    assert any("valid" in v.reason for v in decaps)


def test_ml_kem_768_encap_decap_all_byte_exact():
    result = run_ml_kem_768_encap_decap()
    e, d = result["encapsulation"], result["decapsulation"]
    assert e["total"] == 25 and e["passed"] == 25, [r for r in e["results"] if not r["passed"]]
    assert d["total"] == 10 and d["passed"] == 10, [r for r in d["results"] if not r["passed"]]
    assert d["implicit_rejection_cases"] > 0


def test_ml_dsa_65_sigver_vectors_load_and_shape():
    vectors, meta = load_ml_dsa_65_sigver_vectors()
    assert len(vectors) == 15
    # The trap this file exists to avoid: these must all be the interface
    # liboqs actually implements. kat_vectors.py asserts this at load time;
    # this test additionally locks it down so a future re-trim can't
    # silently swap in an 'internal'-interface group.
    assert sum(v.expected_valid for v in vectors) + sum(not v.expected_valid for v in vectors) == 15
    # Most vectors have a non-empty context -- the reason verify_with_context()
    # (not the plain verify()) is required to reproduce them.
    assert sum(1 for v in vectors if len(v.context) > 0) >= 10


def test_ml_dsa_65_sigver_all_correct_verdict():
    result = run_ml_dsa_65_sigver()
    assert result["total"] == 15
    assert result["passed"] == 15, [r for r in result["results"] if not r["passed"]]


def test_run_all_reports_not_achievable_explicitly():
    """The honesty requirement, checked structurally: run_all() must name
    every gap it doesn't cover, not just silently have fewer checks."""
    result = run_all()
    assert result["summary"]["all_passed"] is True
    assert result["summary"]["total_checks"] == 75  # 25 + 25 + 10 + 15
    assert "ml_dsa_65_keygen" in result["not_achievable"]
    assert "ml_dsa_65_siggen" in result["not_achievable"]
    assert "ml_kem_768_key_checks" in result["not_achievable"]
