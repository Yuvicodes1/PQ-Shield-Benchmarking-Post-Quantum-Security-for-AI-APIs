"""Loads and parses the trimmed NIST ACVP known-answer-test vectors in
validation/vectors/.

This module only does I/O and hex/base64-adjacent decoding -- it has no
opinion about liboqs or ctypes. validation/nist_kat.py is the module that
actually runs the vectors through PQ-Shield's bindings; keeping the two
separate means the vector-parsing logic can be unit-tested (and re-used by
a future ML-KEM-512/1024 or ML-DSA-44/87 harness) without touching liboqs.

Vector provenance: every file here is a trimmed subset of NIST's own ACVP
server test-vector generator output --
https://github.com/usnistgov/ACVP-Server, `gen-val/json-files/`, U.S.
Government work (public domain, 17 U.S.C. 105). These are the same vectors
FIPS 140 validation labs use. Each trimmed file records its exact upstream
URL and fetch date under a `_source`/`_fetched` key, and a `_note` key
explaining what was dropped and why. Run `validation/vectors/fetch.sh` to
re-download the full untrimmed files for independent verification that
nothing was cherry-picked.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

_VECTORS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors")


def _load(filename: str) -> dict:
    path = os.path.join(_VECTORS_DIR, filename)
    with open(path) as f:
        return json.load(f)


def _hx(s: str) -> bytes:
    return bytes.fromhex(s)


# ---------------------------------------------------------------------------
# ML-KEM-768 keyGen
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KeyGenVector:
    tc_id: int
    d: bytes
    z: bytes
    ek: bytes  # expected public (encapsulation) key
    dk: bytes  # expected secret (decapsulation) key

    @property
    def coins(self) -> bytes:
        """FIPS 203 Algorithm 16 takes `d || z` as its 64-byte random input."""
        return self.d + self.z


def load_ml_kem_768_keygen_vectors() -> tuple[list[KeyGenVector], dict]:
    """Returns (vectors, provenance_meta)."""
    doc = _load("ml_kem_768_keygen.json")
    group = doc["testGroups"][0]
    assert group["parameterSet"] == "ML-KEM-768"
    vectors = [
        KeyGenVector(
            tc_id=t["tcId"],
            d=_hx(t["d"]),
            z=_hx(t["z"]),
            ek=_hx(t["ek"]),
            dk=_hx(t["dk"]),
        )
        for t in group["tests"]
    ]
    meta = {"source": doc["_source"], "fetched": doc["_fetched"], "note": doc["_note"]}
    return vectors, meta


# ---------------------------------------------------------------------------
# ML-KEM-768 encaps (AFT) / decaps (VAL)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EncapsVector:
    tc_id: int
    ek: bytes
    m: bytes  # 32-byte randomness (FIPS 203 Algorithm 17's `m`)
    expected_c: bytes
    expected_k: bytes


@dataclass(frozen=True)
class DecapsVector:
    tc_id: int
    dk: bytes
    c: bytes
    expected_k: bytes
    reason: str  # "valid decapsulation" or "modified ciphertext" (implicit rejection)


def load_ml_kem_768_encap_decap_vectors() -> tuple[list[EncapsVector], list[DecapsVector], dict]:
    doc = _load("ml_kem_768_encap_decap.json")
    groups = {g["function"]: g for g in doc["testGroups"]}
    assert set(groups) == {"encapsulation", "decapsulation"}, sorted(groups)

    encaps = [
        EncapsVector(
            tc_id=t["tcId"],
            ek=_hx(t["ek"]),
            m=_hx(t["m"]),
            expected_c=_hx(t["c"]),
            expected_k=_hx(t["k"]),
        )
        for t in groups["encapsulation"]["tests"]
    ]
    decaps = [
        DecapsVector(
            tc_id=t["tcId"],
            dk=_hx(t["dk"]),
            c=_hx(t["c"]),
            expected_k=_hx(t["k"]),
            reason=t.get("reason", ""),
        )
        for t in groups["decapsulation"]["tests"]
    ]
    meta = {"source": doc["_source"], "fetched": doc["_fetched"], "note": doc["_note"]}
    return encaps, decaps, meta


# ---------------------------------------------------------------------------
# ML-DSA-65 sigVer (external / pure interface only -- see module docstring
# in validation/nist_kat.py for why the other three group variants in the
# upstream file are not applicable to liboqs)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SigVerVector:
    tc_id: int
    pk: bytes
    message: bytes
    context: bytes
    signature: bytes
    expected_valid: bool
    reason: str


def load_ml_dsa_65_sigver_vectors() -> tuple[list[SigVerVector], dict]:
    doc = _load("ml_dsa_65_sigver.json")
    group = doc["testGroups"][0]
    assert group["parameterSet"] == "ML-DSA-65"
    assert group["signatureInterface"] == "external"
    assert group["preHash"] == "pure"

    vectors = [
        SigVerVector(
            tc_id=t["tcId"],
            pk=_hx(t["pk"]),
            message=_hx(t["message"]),
            context=_hx(t.get("context", "")),
            signature=_hx(t["signature"]),
            expected_valid=bool(t["testPassed"]),
            reason=t.get("reason", ""),
        )
        for t in group["tests"]
    ]
    meta = {"source": doc["_source"], "fetched": doc["_fetched"], "note": doc["_note"]}
    return vectors, meta
