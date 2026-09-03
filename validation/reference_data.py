"""External ground-truth reference data for validating PQ-Shield's measurements.

Everything in this file is a *published* value from a normative standard or
peer-reviewed/archival source -- none of it is measured by this project. It
exists so `validation/spec_conformance.py` and `validation/primitive_bench.py`
can check PQ-Shield's own implementation against something a reviewer can
independently verify, rather than against itself.

Two categories:

1. NORMATIVE parameter sizes (FIPS 203 / FIPS 204). These are exact and
   hardware-independent -- an implementation either produces them or is
   wrong. This is the strongest single validation available: if PQ-Shield's
   ctypes binding to liboqs emits exactly the byte counts NIST mandates,
   the binding is demonstrably correct at the interface level.

2. INDICATIVE published throughput figures. These are hardware-dependent and
   are NOT expected to match this project's absolute numbers. They are
   recorded so the paper can argue that PQ-Shield's *relative* orderings and
   ratios are consistent with independently published results, which is the
   defensible claim for a single-host benchmark.

A note on a real discrepancy in the literature, worth stating explicitly in
the paper because a reviewer may otherwise flag PQ-Shield's numbers as wrong:
several sources published after August 2024 still cite ML-DSA-65 as having a
3,293-byte signature and a 4,000-byte private key. Those are the
*pre-standardisation* CRYSTALS-Dilithium3 (NIST Round 3) values. FIPS 204 as
finalised specifies 3,309 bytes and 4,032 bytes respectively. PQ-Shield
measures the FIPS 204 final values. Citing this difference pre-empts the
objection and demonstrates the implementation tracks the final standard.
"""

from __future__ import annotations

from dataclasses import dataclass


# ---------------------------------------------------------------------------
# 1. Normative parameter sizes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KEMParameters:
    name: str
    security_category: int
    public_key_bytes: int
    secret_key_bytes: int
    ciphertext_bytes: int
    shared_secret_bytes: int
    source: str


@dataclass(frozen=True)
class SignatureParameters:
    name: str
    security_category: int
    public_key_bytes: int
    secret_key_bytes: int
    signature_bytes: int
    source: str


FIPS_203_ML_KEM_768 = KEMParameters(
    name="ML-KEM-768",
    security_category=3,
    public_key_bytes=1184,
    secret_key_bytes=2400,
    ciphertext_bytes=1088,
    shared_secret_bytes=32,
    source=(
        "NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard, "
        "August 2024, Table 2 (parameter sets)."
    ),
)

FIPS_204_ML_DSA_65 = SignatureParameters(
    name="ML-DSA-65",
    security_category=3,
    public_key_bytes=1952,
    secret_key_bytes=4032,
    signature_bytes=3309,
    source=(
        "NIST FIPS 204, Module-Lattice-Based Digital Signature Standard, August 2024, "
        "Table 2 (sizes in bytes of keys and signatures of ML-DSA)."
    ),
)

# Pre-standardisation values still circulating in the literature. Recorded so
# spec_conformance.py can explicitly report "measured value matches FIPS 204
# final, NOT the superseded Round 3 value" rather than leaving it ambiguous.
ROUND3_DILITHIUM3_SUPERSEDED = SignatureParameters(
    name="Dilithium3 (superseded, NIST Round 3)",
    security_category=3,
    public_key_bytes=1952,
    secret_key_bytes=4000,
    signature_bytes=3293,
    source=(
        "CRYSTALS-Dilithium Round 3 specification. Superseded by FIPS 204 (August 2024). "
        "Still cited in some post-2024 publications; see docs/DESIGN.md."
    ),
)

# Classical baselines, for the size-comparison table.
CLASSICAL_REFERENCE = {
    "RSA-2048-OAEP": {
        "ciphertext_bytes": 256,
        "note": "RSA-2048 produces a 256-byte (2048-bit) ciphertext block.",
        "source": "RFC 8017 (PKCS #1 v2.2), modulus length k = 256 bytes for RSA-2048.",
    },
    "ECDSA-P256": {
        "signature_bytes_raw": 64,
        "signature_bytes_der_typical": 70,
        "note": (
            "Raw (r||s) ECDSA P-256 signatures are 64 bytes. The DER encoding used by "
            "the `cryptography` library adds ASN.1 framing, typically yielding 70-72 "
            "bytes, which is what PQ-Shield measures on the wire."
        ),
        "source": "SEC 1 / RFC 3279 ECDSA-Sig-Value DER encoding.",
    },
}


# ---------------------------------------------------------------------------
# 2. Indicative published throughput (hardware-dependent -- ordering only)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PublishedThroughput:
    platform: str
    algorithm: str
    operation: str
    ops_per_second: float
    source: str


# These are deliberately drawn from different hardware classes to make the
# point that absolute numbers vary by more than an order of magnitude across
# platforms -- which is exactly why PQ-Shield reports relative overhead
# ratios as its primary result and absolute milliseconds as secondary.
PUBLISHED_THROUGHPUT = [
    PublishedThroughput(
        platform="Raspberry Pi 4B (ARM Cortex-A72)",
        algorithm="ML-KEM-768", operation="keygen", ops_per_second=2539.0,
        source="Post-Quantum Migration of Tor, arXiv:2503.10238, Table 8 (liboqs).",
    ),
    PublishedThroughput(
        platform="Raspberry Pi 4B (ARM Cortex-A72)",
        algorithm="ML-KEM-768", operation="encaps", ops_per_second=3905.0,
        source="Post-Quantum Migration of Tor, arXiv:2503.10238, Table 8 (liboqs).",
    ),
    PublishedThroughput(
        platform="Raspberry Pi 4B (ARM Cortex-A72)",
        algorithm="ML-KEM-768", operation="decaps", ops_per_second=2571.5,
        source="Post-Quantum Migration of Tor, arXiv:2503.10238, Table 8 (liboqs).",
    ),
    PublishedThroughput(
        platform="Raspberry Pi 5 (ARM Cortex-A76)",
        algorithm="ML-KEM-768", operation="keygen", ops_per_second=13976.6,
        source="Post-Quantum Migration of Tor, arXiv:2503.10238, Table 8 (liboqs).",
    ),
    PublishedThroughput(
        platform="Raspberry Pi 5 (ARM Cortex-A76)",
        algorithm="ML-KEM-768", operation="encaps", ops_per_second=11900.6,
        source="Post-Quantum Migration of Tor, arXiv:2503.10238, Table 8 (liboqs).",
    ),
    PublishedThroughput(
        platform="Raspberry Pi 5 (ARM Cortex-A76)",
        algorithm="ML-KEM-768", operation="decaps", ops_per_second=9614.3,
        source="Post-Quantum Migration of Tor, arXiv:2503.10238, Table 8 (liboqs).",
    ),
]

# Qualitative orderings that any correct implementation on any hardware should
# reproduce. These are the claims PQ-Shield's own measurements are checked
# against in validation/primitive_bench.py -- they hold regardless of platform,
# unlike absolute throughput.
EXPECTED_QUALITATIVE_ORDERINGS = [
    {
        "claim": "ML-DSA-65 verification is faster than ML-DSA-65 signing",
        "rationale": (
            "ML-DSA signing uses Fiat-Shamir with Aborts: rejection sampling means "
            "signing repeats until a norm check passes (expected ~5.1 iterations at "
            "security level 3), while verification is single-pass and deterministic."
        ),
        "source": (
            "FIPS 204 Sec. 6; Benchmarking ML-KEM/ML-DSA on Cortex-M0+, arXiv:2603.19340, "
            "Sec. IV-B (signing variance, deterministic verification)."
        ),
    },
    {
        "claim": "ML-DSA-65 signatures are roughly 50x larger than ECDSA P-256 signatures",
        "rationale": "3309 bytes vs 64 bytes raw = 51.7x.",
        "source": "FIPS 204 Table 2 vs SEC 1 ECDSA P-256.",
    },
    {
        "claim": "ML-KEM-768 key generation is faster than RSA-2048 key generation",
        "rationale": (
            "RSA keygen requires probabilistic prime search; ML-KEM keygen is "
            "deterministic-time polynomial arithmetic. This is the mechanism behind "
            "PQ-Shield's availability finding at high concurrency."
        ),
        "source": (
            "A Practical Performance Benchmark of Post-Quantum Cryptography Across "
            "Heterogeneous Computing Environments, Cryptography 9(1):12, 2025."
        ),
    },
]
