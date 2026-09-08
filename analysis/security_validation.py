"""Ground-truth cross-checks between the trade-off matrix's categorical
security assumptions (analysis.tradeoff_matrix.SECURITY_SCORES) and what the
live threat-scenario experiments (Threat Scenarios page / threats/*.py)
actually measured. Two checks, deliberately kept separate since they answer
different questions:

  - validate_confidentiality_axis: does each config's *measured*
    kex_decryptable_under_future_crqc flag (from an HNDL capture,
    results/hndl/*-summary.json) agree with what SECURITY_SCORES implicitly
    asserts (classical's RSA key-establishment decryptable under a future
    CRQC; hybrid/full_pqc's ML-KEM-768 not)? A mismatch here would mean the
    composite score is asserting something the experiments on disk don't
    support -- this must never silently pass.

  - validate_authenticity_near_term: what MITM signature-tamper detection
    rate did each config actually achieve (results/mitm/*-summary.json)?
    This is NOT fed into SECURITY_SCORES or streaming_security_score -- see
    analysis/tradeoff_matrix.py's module docstring and docs/DESIGN.md's "A
    note on baselines" / "Streaming security score" sections for why:
    near-term detection rate and future-quantum-forgery resistance are
    different properties, and a correctly-implemented ECDSA and a
    correctly-implemented ML-DSA-65 should both detect a tampered byte
    close to 100% of the time near-term -- that similarity is expected, not
    informative. This function exists to confirm that expectation actually
    holds on real data, which is *why* authenticity is scored as a
    categorical property rather than a rate-based one; if it doesn't hold,
    that's a real, surprising finding worth investigating before
    publication, not something to fold into the score and smooth over.
"""

from __future__ import annotations

from analysis.tradeoff_matrix import SECURITY_SCORES

# What SECURITY_SCORES' ordinal mapping implicitly asserts about
# confidentiality: classical's key-establishment (RSA-2048) is decryptable
# under a future CRQC; hybrid/full_pqc's (ML-KEM-768) is not. Mirrors the
# justification already given in tradeoff_matrix.py's module docstring,
# made checkable against real HNDL capture data.
EXPECTED_KEX_DECRYPTABLE = {"classical": True, "hybrid": False, "full_pqc": False}

# Below this near-term signature-tamper detection rate, the "authenticity is
# a categorical property, not a rate" argument stops being obviously true
# and deserves a second look rather than a pass/fail badge alone.
NEAR_100PCT_THRESHOLD = 0.99


def validate_confidentiality_axis(hndl_summaries: list[dict]) -> list[str]:
    """Returns a list of human-readable mismatch/gap warnings (empty list
    if every config present agrees with EXPECTED_KEX_DECRYPTABLE and every
    expected config has data)."""
    warnings: list[str] = []
    seen = set()
    for s in hndl_summaries:
        config = s.get("config")
        if config not in EXPECTED_KEX_DECRYPTABLE:
            continue
        seen.add(config)
        measured = s.get("kex_decryptable_under_future_crqc")
        expected = EXPECTED_KEX_DECRYPTABLE[config]
        if measured is None:
            warnings.append(f"{config}: HNDL summary has no kex_decryptable_under_future_crqc field.")
        elif measured != expected:
            warnings.append(
                f"{config}: measured kex_decryptable_under_future_crqc={measured}, but SECURITY_SCORES "
                f"implies {expected} -- the composite score's confidentiality assumption for this config "
                "is NOT supported by the HNDL data currently on disk."
            )
    missing = set(EXPECTED_KEX_DECRYPTABLE) - seen
    if missing:
        warnings.append(
            f"No HNDL summary on disk yet for: {', '.join(sorted(missing))} -- confidentiality "
            "assumption unverified for these configs (run the HNDL tab on the Threat Scenarios page)."
        )
    return warnings


def validate_authenticity_near_term(mitm_summaries: list[dict]) -> dict:
    """{"per_config_detection_rate": {...}, "all_near_100pct": bool, "note": str}."""
    per_config = {
        s["config"]: s.get("detection_rate")
        for s in mitm_summaries
        if s.get("tamper_target") == "signature" and s.get("config") in SECURITY_SCORES
    }
    rates = [r for r in per_config.values() if r is not None]
    all_high = bool(rates) and min(rates) >= NEAR_100PCT_THRESHOLD
    note = (
        "Uniformly high near-term detection across configs -- this is what justifies scoring "
        "authenticity as a categorical future-quantum-forgery property (SECURITY_SCORES) rather than "
        "a near-term detection-rate differentiator. ECDSA and ML-DSA-65 both catch a tampered byte "
        "today; the real difference this score captures is whether a forged signature could be "
        "produced *at all* once a CRQC exists, which a detection-rate number cannot measure."
        if all_high else
        "WARNING: near-term signature-tamper detection is NOT uniformly high (>=99%) across every "
        "config with data -- this contradicts the assumption behind scoring authenticity as a purely "
        "categorical property. Investigate before citing SECURITY_SCORES' authenticity ordering as-is."
        if rates else
        "No signature-tamper MITM results on disk yet (run the MITM tab on the Threat Scenarios page) "
        "-- the near-term-detection-rate assumption behind SECURITY_SCORES' authenticity axis is "
        "currently unverified."
    )
    return {"per_config_detection_rate": per_config, "all_near_100pct": all_high, "note": note}
