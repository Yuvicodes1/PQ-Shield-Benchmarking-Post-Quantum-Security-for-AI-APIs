"""Runs PQ-Shield's liboqs ctypes bindings against NIST's own ACVP
known-answer-test (KAT) vectors -- the same vectors used for FIPS 140
validation. This is the strongest ground truth available for ML-KEM and
ML-DSA correctness: validation/spec_conformance.py checks that PQ-Shield's
*byte lengths* match the standard; this module checks that the actual
*cryptographic output*, byte-for-byte, matches NIST's own reference
computation for fixed, published inputs.

WHAT IS AND ISN'T ACHIEVABLE THROUGH liboqs's PUBLIC API
----------------------------------------------------------
  ML-KEM-768 keyGen    ACHIEVABLE.  liboqs exports
                        OQS_KEM_ml_kem_768_keypair_derand(pk, sk, coins),
                        which takes FIPS 203 Algorithm 16's 64-byte `d||z`
                        randomness explicitly. Byte-exact.

  ML-KEM-768 encaps     ACHIEVABLE.  OQS_KEM_ml_kem_768_encaps_derand takes
                        Algorithm 17's 32-byte `m` explicitly. Byte-exact.

  ML-KEM-768 decaps     ACHIEVABLE.  Decapsulation has no randomness to
                        control in the first place -- OQS_KEM_ml_kem_768_decaps
                        is used as-is. Covers both "valid ciphertext" and
                        "modified ciphertext" (implicit-rejection) vectors,
                        which is a meaningful correctness check: implicit
                        rejection is an easy detail to get subtly wrong and
                        NIST's vectors specifically exercise it.

  ML-KEM-768 key checks NOT ACHIEVABLE.  The upstream encapDecap file also
                        has 'encapsulationKeyCheck'/'decapsulationKeyCheck'
                        groups, which test whether a given (possibly
                        malformed) key is structurally valid per FIPS 203's
                        key-check procedure. liboqs's public API has no
                        exposed entrypoint that performs this check in
                        isolation -- encaps/decaps just operate on whatever
                        bytes they're given. Testing this would mean
                        re-implementing FIPS 203's key-validation logic
                        ourselves and comparing that reimplementation's
                        verdict to NIST's, which tests our own code against
                        itself, not liboqs -- not a KAT. Dropped from the
                        trimmed vector file for this reason (see its
                        `_note` key); not silently skipped, documented here.

  ML-DSA-65 sigVer      ACHIEVABLE, WITH A TRAP -- read this before
                        re-running or extending this module. NIST's sigVer
                        vectors for ML-DSA-65 come in four group variants:

                            signatureInterface=external, preHash=pure
                            signatureInterface=external, preHash=preHash
                            signatureInterface=internal, externalMu=true
                            signatureInterface=internal, externalMu=false

                        liboqs implements ONLY the external+pure interface
                        (FIPS 204 Algorithm 3, ML-DSA.Verify, the ordinary
                        "verify a signature over a message" entrypoint).
                        The 'internal' groups exercise FIPS 204's internal
                        ML-DSA.Verify_internal, which operates on a raw
                        pre-hashed `mu` value liboqs's public API does not
                        expose. Running this harness against an 'internal'
                        group produces a result that LOOKS like a partial
                        failure (12/15, not 0/15 or 15/15) but is purely an
                        interface mismatch, not a correctness bug -- the
                        3 "passing" cases are the ones whose expected
                        outcome happens to be rejection anyway, which the
                        wrong interface also rejects for the wrong reason.
                        This cost real debugging time before being
                        understood; the trimmed vector file keeps only the
                        external+pure group specifically to avoid this trap
                        recurring. If you ever regenerate the trimmed file
                        from a fresh upstream download, filter groups with
                        exactly signatureInterface == "external" and
                        preHash == "pure" -- see kat_vectors.py.

  ML-DSA-65 keyGen      NOT ACHIEVABLE.  liboqs does not export an
  ML-DSA-65 sigGen      OQS_SIG_ml_dsa_65_keypair_derand (or any
                        deterministic-input keygen), and its
                        OQS_SIG_ml_dsa_65_sign is randomized (hedged) by
                        default with no derandomized variant exposed either.
                        There is therefore no way to reproduce NIST's exact
                        published (pk, sk) or signature bytes for keyGen or
                        sigGen through liboqs's public API -- only sigVer,
                        which takes an externally supplied signature and
                        only needs to reach the same accept/reject verdict,
                        is achievable. This is a real, structural limitation
                        of what liboqs exposes, not a shortcut taken here.
                        Round-tripping PQ-Shield's own sign() output through
                        its own verify() (as spec_conformance.py already
                        does) is a correctness sanity check, not a KAT --
                        it can't catch a bug that's consistent between sign
                        and verify, which is exactly the failure mode a KAT
                        exists to catch. This module does not attempt to
                        pass that off as sigGen/keyGen coverage.

Run:
    python -m validation.nist_kat
    python -m validation.nist_kat --json
    python -m validation.nist_kat --output results/validation/nist_kat.json
"""

from __future__ import annotations

import argparse
import json
import os

from crypto.oqs_adapter import MLDSA65, MLKEM768
from validation.kat_vectors import (
    load_ml_dsa_65_sigver_vectors,
    load_ml_kem_768_encap_decap_vectors,
    load_ml_kem_768_keygen_vectors,
)


def run_ml_kem_768_keygen() -> dict:
    vectors, meta = load_ml_kem_768_keygen_vectors()
    results = []
    for v in vectors:
        kp = MLKEM768.keypair_derand(v.coins)
        results.append({
            "tcId": v.tc_id,
            "ek_match": kp.public_key == v.ek,
            "dk_match": kp.secret_key == v.dk,
            "passed": kp.public_key == v.ek and kp.secret_key == v.dk,
        })
    return {
        "provenance": meta,
        "results": results,
        "passed": sum(r["passed"] for r in results),
        "total": len(results),
    }


def run_ml_kem_768_encap_decap() -> dict:
    encaps_vectors, decaps_vectors, meta = load_ml_kem_768_encap_decap_vectors()

    encaps_results = []
    for v in encaps_vectors:
        ct, ss = MLKEM768.encaps_derand(v.ek, v.m)
        encaps_results.append({
            "tcId": v.tc_id,
            "c_match": ct == v.expected_c,
            "k_match": ss == v.expected_k,
            "passed": ct == v.expected_c and ss == v.expected_k,
        })

    decaps_results = []
    for v in decaps_vectors:
        ss = MLKEM768.decaps(v.c, v.dk)
        decaps_results.append({
            "tcId": v.tc_id,
            "reason": v.reason,
            "k_match": ss == v.expected_k,
            "passed": ss == v.expected_k,
        })

    return {
        "provenance": meta,
        "encapsulation": {
            "results": encaps_results,
            "passed": sum(r["passed"] for r in encaps_results),
            "total": len(encaps_results),
        },
        "decapsulation": {
            "results": decaps_results,
            "implicit_rejection_cases": sum(1 for r in decaps_results if "modified" in r["reason"]),
            "passed": sum(r["passed"] for r in decaps_results),
            "total": len(decaps_results),
        },
    }


def run_ml_dsa_65_sigver() -> dict:
    vectors, meta = load_ml_dsa_65_sigver_vectors()
    results = []
    for v in vectors:
        actual_valid = MLDSA65.verify_with_context(v.message, v.signature, v.context, v.pk)
        results.append({
            "tcId": v.tc_id,
            "reason": v.reason,
            "context_bytes": len(v.context),
            "expected_valid": v.expected_valid,
            "actual_valid": actual_valid,
            "passed": actual_valid == v.expected_valid,
        })
    return {
        "provenance": meta,
        "results": results,
        "passed": sum(r["passed"] for r in results),
        "total": len(results),
    }


def run_all() -> dict:
    keygen = run_ml_kem_768_keygen()
    encap_decap = run_ml_kem_768_encap_decap()
    sigver = run_ml_dsa_65_sigver()

    total_passed = (
        keygen["passed"]
        + encap_decap["encapsulation"]["passed"] + encap_decap["decapsulation"]["passed"]
        + sigver["passed"]
    )
    total = (
        keygen["total"]
        + encap_decap["encapsulation"]["total"] + encap_decap["decapsulation"]["total"]
        + sigver["total"]
    )

    return {
        "ml_kem_768_keygen": keygen,
        "ml_kem_768_encap_decap": encap_decap,
        "ml_dsa_65_sigver": sigver,
        "not_achievable": {
            "ml_kem_768_key_checks": "liboqs exposes no isolated key-validation entrypoint -- see module docstring",
            "ml_dsa_65_keygen": "liboqs exports no OQS_SIG_ml_dsa_65_keypair_derand -- see module docstring",
            "ml_dsa_65_siggen": "OQS_SIG_ml_dsa_65_sign is randomized/hedged with no derandomized variant -- see module docstring",
        },
        "summary": {
            "total_checks": total,
            "passed": total_passed,
            "all_passed": total_passed == total,
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="PQ-Shield vs. NIST ACVP known-answer-test vectors (ML-KEM-768 / ML-DSA-65)"
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--output", default=None, help="Write JSON to this path as well")
    args = parser.parse_args()

    results = run_all()

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)

    if args.json:
        print(json.dumps(results, indent=2))
        return

    print("=" * 78)
    print("PQ-Shield vs. NIST ACVP known-answer-test vectors")
    print("=" * 78)

    kg = results["ml_kem_768_keygen"]
    print(f"\nML-KEM-768 keyGen (derandomized, FIPS 203 Algorithm 16)")
    print(f"  {kg['passed']}/{kg['total']} byte-exact")

    ed = results["ml_kem_768_encap_decap"]
    e, d = ed["encapsulation"], ed["decapsulation"]
    print(f"\nML-KEM-768 encapsulation (AFT, derandomized, FIPS 203 Algorithm 17)")
    print(f"  {e['passed']}/{e['total']} byte-exact")
    print(f"\nML-KEM-768 decapsulation (VAL, incl. {d['implicit_rejection_cases']} implicit-rejection cases)")
    print(f"  {d['passed']}/{d['total']} byte-exact")

    sv = results["ml_dsa_65_sigver"]
    print(f"\nML-DSA-65 signature verification (external/pure interface, FIPS 204 Algorithm 3)")
    print(f"  {sv['passed']}/{sv['total']} correct accept/reject verdict")
    n_empty_ctx = sum(1 for r in sv["results"] if r["context_bytes"] == 0)
    print(f"  ({n_empty_ctx}/{sv['total']} vectors use an empty context string; "
          f"the other {sv['total'] - n_empty_ctx} required verify_with_context())")

    print("\nNot achievable through liboqs's public API (documented, not silently skipped)")
    print("-" * 78)
    for k, v in results["not_achievable"].items():
        print(f"  - {k}: {v}")

    s = results["summary"]
    print("\n" + "=" * 78)
    print(f"{s['passed']}/{s['total_checks']} KAT checks passed"
          f"{'  -- ALL PASS' if s['all_passed'] else '  -- FAILURES PRESENT'}")
    print("=" * 78)


if __name__ == "__main__":
    main()
