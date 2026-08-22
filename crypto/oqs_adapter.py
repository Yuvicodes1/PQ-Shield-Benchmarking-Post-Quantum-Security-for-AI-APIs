"""
Minimal ctypes adapter around a locally built liboqs shared library.

This intentionally avoids the `liboqs-python` package and instead binds
directly to the per-algorithm exported C functions for exactly the two
mechanisms this project needs:

    - ML-KEM-768   (FIPS 203)  -- key encapsulation
    - ML-DSA-65    (FIPS 204)  -- digital signatures

Rationale (see docs/DESIGN.md): binding two fixed-size algorithms directly
is simpler and more auditable than parsing the generic `OQS_KEM` /
`OQS_SIG` C structs (which contain function pointers and are sensitive to
compiler struct-padding), and it keeps the dependency footprint small
enough to build liboqs from source in CI without a system-wide install.

The exact byte lengths below are compile-time constants taken from
`oqs-prefix/include/oqs/kem_ml_kem.h` and `.../sig_ml_dsa.h` in this
repository's own liboqs build; they are NOT guessed. `scripts/install_oqs.sh`
rebuilds the same library revision, and `verify_algorithms()` below sanity
checks the library at import time so a mismatched build fails loudly
instead of silently returning corrupt keys.
"""

from __future__ import annotations

import ctypes
import os
from ctypes import c_int, c_size_t, c_uint8, c_void_p, byref
from dataclasses import dataclass


class OQSAdapterError(RuntimeError):
    """Raised when the underlying liboqs call reports failure."""


def _locate_liboqs() -> str:
    """Resolve the liboqs shared library path.

    Priority:
      1. PQ_SHIELD_OQS_LIB env var (absolute path to .so/.dylib) -- lets a
         user point at any local liboqs build, per the project README.
      2. The repo-local build under oqs-prefix/lib produced by
         scripts/install_oqs.sh.
    """
    override = os.environ.get("PQ_SHIELD_OQS_LIB")
    if override:
        if not os.path.isfile(override):
            raise OQSAdapterError(f"PQ_SHIELD_OQS_LIB points to a missing file: {override}")
        return override

    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(here, "oqs-prefix", "lib", "liboqs.so"),
        os.path.join(here, "oqs-prefix", "lib", "liboqs.dylib"),
        os.path.join(here, "oqs-prefix", "lib64", "liboqs.so"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    raise OQSAdapterError(
        "Could not locate liboqs shared library. Run scripts/install_oqs.sh "
        "or set PQ_SHIELD_OQS_LIB to an absolute path."
    )


_lib = ctypes.CDLL(_locate_liboqs())

# OQS_STATUS: OQS_SUCCESS = 0, OQS_ERROR = -1 (see oqs/oqs.h)
OQS_SUCCESS = 0

# ---------------------------------------------------------------------------
# ML-KEM-768 (FIPS 203) -- fixed byte lengths from kem_ml_kem.h
# ---------------------------------------------------------------------------
ML_KEM_768_PUBLIC_KEY_BYTES = 1184
ML_KEM_768_SECRET_KEY_BYTES = 2400
ML_KEM_768_CIPHERTEXT_BYTES = 1088
ML_KEM_768_SHARED_SECRET_BYTES = 32

_lib.OQS_KEM_ml_kem_768_keypair.argtypes = [c_void_p, c_void_p]
_lib.OQS_KEM_ml_kem_768_keypair.restype = c_int

_lib.OQS_KEM_ml_kem_768_encaps.argtypes = [c_void_p, c_void_p, c_void_p]
_lib.OQS_KEM_ml_kem_768_encaps.restype = c_int

_lib.OQS_KEM_ml_kem_768_decaps.argtypes = [c_void_p, c_void_p, c_void_p]
_lib.OQS_KEM_ml_kem_768_decaps.restype = c_int


@dataclass
class KemKeypair:
    public_key: bytes
    secret_key: bytes


class MLKEM768:
    """ML-KEM-768 key encapsulation, per FIPS 203."""

    ALGORITHM = "ML-KEM-768"
    PUBLIC_KEY_BYTES = ML_KEM_768_PUBLIC_KEY_BYTES
    SECRET_KEY_BYTES = ML_KEM_768_SECRET_KEY_BYTES
    CIPHERTEXT_BYTES = ML_KEM_768_CIPHERTEXT_BYTES
    SHARED_SECRET_BYTES = ML_KEM_768_SHARED_SECRET_BYTES

    @staticmethod
    def keypair() -> KemKeypair:
        pk = (c_uint8 * ML_KEM_768_PUBLIC_KEY_BYTES)()
        sk = (c_uint8 * ML_KEM_768_SECRET_KEY_BYTES)()
        rc = _lib.OQS_KEM_ml_kem_768_keypair(byref(pk), byref(sk))
        if rc != OQS_SUCCESS:
            raise OQSAdapterError("OQS_KEM_ml_kem_768_keypair failed")
        return KemKeypair(bytes(pk), bytes(sk))

    @staticmethod
    def encaps(public_key: bytes) -> tuple[bytes, bytes]:
        """Returns (ciphertext, shared_secret)."""
        if len(public_key) != ML_KEM_768_PUBLIC_KEY_BYTES:
            raise OQSAdapterError(
                f"ML-KEM-768 public key must be {ML_KEM_768_PUBLIC_KEY_BYTES} bytes, "
                f"got {len(public_key)}"
            )
        ct = (c_uint8 * ML_KEM_768_CIPHERTEXT_BYTES)()
        ss = (c_uint8 * ML_KEM_768_SHARED_SECRET_BYTES)()
        pk_buf = (c_uint8 * len(public_key)).from_buffer_copy(public_key)
        rc = _lib.OQS_KEM_ml_kem_768_encaps(byref(ct), byref(ss), byref(pk_buf))
        if rc != OQS_SUCCESS:
            raise OQSAdapterError("OQS_KEM_ml_kem_768_encaps failed")
        return bytes(ct), bytes(ss)

    @staticmethod
    def decaps(ciphertext: bytes, secret_key: bytes) -> bytes:
        """Returns shared_secret."""
        if len(ciphertext) != ML_KEM_768_CIPHERTEXT_BYTES:
            raise OQSAdapterError(
                f"ML-KEM-768 ciphertext must be {ML_KEM_768_CIPHERTEXT_BYTES} bytes, "
                f"got {len(ciphertext)}"
            )
        if len(secret_key) != ML_KEM_768_SECRET_KEY_BYTES:
            raise OQSAdapterError("ML-KEM-768 secret key has unexpected length")
        ss = (c_uint8 * ML_KEM_768_SHARED_SECRET_BYTES)()
        ct_buf = (c_uint8 * len(ciphertext)).from_buffer_copy(ciphertext)
        sk_buf = (c_uint8 * len(secret_key)).from_buffer_copy(secret_key)
        rc = _lib.OQS_KEM_ml_kem_768_decaps(byref(ss), byref(ct_buf), byref(sk_buf))
        if rc != OQS_SUCCESS:
            raise OQSAdapterError("OQS_KEM_ml_kem_768_decaps failed")
        return bytes(ss)


# ---------------------------------------------------------------------------
# ML-DSA-65 (FIPS 204) -- fixed byte lengths from sig_ml_dsa.h
# ---------------------------------------------------------------------------
ML_DSA_65_PUBLIC_KEY_BYTES = 1952
ML_DSA_65_SECRET_KEY_BYTES = 4032
ML_DSA_65_SIGNATURE_MAX_BYTES = 3309

_lib.OQS_SIG_ml_dsa_65_keypair.argtypes = [c_void_p, c_void_p]
_lib.OQS_SIG_ml_dsa_65_keypair.restype = c_int

_lib.OQS_SIG_ml_dsa_65_sign.argtypes = [
    c_void_p, c_void_p, c_void_p, c_size_t, c_void_p,
]
_lib.OQS_SIG_ml_dsa_65_sign.restype = c_int

_lib.OQS_SIG_ml_dsa_65_verify.argtypes = [
    c_void_p, c_size_t, c_void_p, c_size_t, c_void_p,
]
_lib.OQS_SIG_ml_dsa_65_verify.restype = c_int


@dataclass
class SigKeypair:
    public_key: bytes
    secret_key: bytes


class MLDSA65:
    """ML-DSA-65 digital signatures, per FIPS 204."""

    ALGORITHM = "ML-DSA-65"
    PUBLIC_KEY_BYTES = ML_DSA_65_PUBLIC_KEY_BYTES
    SECRET_KEY_BYTES = ML_DSA_65_SECRET_KEY_BYTES
    SIGNATURE_MAX_BYTES = ML_DSA_65_SIGNATURE_MAX_BYTES

    @staticmethod
    def keypair() -> SigKeypair:
        pk = (c_uint8 * ML_DSA_65_PUBLIC_KEY_BYTES)()
        sk = (c_uint8 * ML_DSA_65_SECRET_KEY_BYTES)()
        rc = _lib.OQS_SIG_ml_dsa_65_keypair(byref(pk), byref(sk))
        if rc != OQS_SUCCESS:
            raise OQSAdapterError("OQS_SIG_ml_dsa_65_keypair failed")
        return SigKeypair(bytes(pk), bytes(sk))

    @staticmethod
    def sign(message: bytes, secret_key: bytes) -> bytes:
        if len(secret_key) != ML_DSA_65_SECRET_KEY_BYTES:
            raise OQSAdapterError("ML-DSA-65 secret key has unexpected length")
        sig_buf = (c_uint8 * ML_DSA_65_SIGNATURE_MAX_BYTES)()
        sig_len = c_size_t(0)
        msg_buf = (c_uint8 * len(message)).from_buffer_copy(message) if message else None
        sk_buf = (c_uint8 * len(secret_key)).from_buffer_copy(secret_key)
        rc = _lib.OQS_SIG_ml_dsa_65_sign(
            byref(sig_buf), byref(sig_len), msg_buf, c_size_t(len(message)), byref(sk_buf)
        )
        if rc != OQS_SUCCESS:
            raise OQSAdapterError("OQS_SIG_ml_dsa_65_sign failed")
        return bytes(sig_buf)[: sig_len.value]

    @staticmethod
    def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
        if len(public_key) != ML_DSA_65_PUBLIC_KEY_BYTES:
            raise OQSAdapterError("ML-DSA-65 public key has unexpected length")
        msg_buf = (c_uint8 * len(message)).from_buffer_copy(message) if message else None
        sig_buf = (c_uint8 * len(signature)).from_buffer_copy(signature)
        pk_buf = (c_uint8 * len(public_key)).from_buffer_copy(public_key)
        rc = _lib.OQS_SIG_ml_dsa_65_verify(
            msg_buf, c_size_t(len(message)), byref(sig_buf), c_size_t(len(signature)), byref(pk_buf)
        )
        return rc == OQS_SUCCESS


def verify_algorithms() -> dict:
    """Round-trip self-test, run at server startup so a bad build fails fast."""
    kp = MLKEM768.keypair()
    ct, ss1 = MLKEM768.encaps(kp.public_key)
    ss2 = MLKEM768.decaps(ct, kp.secret_key)
    if ss1 != ss2:
        raise OQSAdapterError("ML-KEM-768 self-test failed: shared secrets do not match")

    skp = MLDSA65.keypair()
    msg = b"pq-shield self-test"
    sig = MLDSA65.sign(msg, skp.secret_key)
    if not MLDSA65.verify(msg, sig, skp.public_key):
        raise OQSAdapterError("ML-DSA-65 self-test failed: valid signature rejected")
    if MLDSA65.verify(b"tampered message", sig, skp.public_key):
        raise OQSAdapterError("ML-DSA-65 self-test failed: tampered message accepted")

    return {
        "ML-KEM-768": {
            "public_key_bytes": MLKEM768.PUBLIC_KEY_BYTES,
            "secret_key_bytes": MLKEM768.SECRET_KEY_BYTES,
            "ciphertext_bytes": MLKEM768.CIPHERTEXT_BYTES,
            "shared_secret_bytes": MLKEM768.SHARED_SECRET_BYTES,
        },
        "ML-DSA-65": {
            "public_key_bytes": MLDSA65.PUBLIC_KEY_BYTES,
            "secret_key_bytes": MLDSA65.SECRET_KEY_BYTES,
            "signature_bytes_observed": len(sig),
            "signature_bytes_max": MLDSA65.SIGNATURE_MAX_BYTES,
        },
    }


if __name__ == "__main__":
    import json

    print(json.dumps(verify_algorithms(), indent=2))
