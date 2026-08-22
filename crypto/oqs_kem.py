"""Minimal, version-compatible ctypes adapter for liboqs ML-KEM-768.

The active project interpreter may be Python 3.9 while current liboqs-python
requires Python 3.10+. This adapter calls liboqs directly and deliberately
exposes only the three ML-KEM operations required by Configuration B.
"""

import ctypes
import os
from pathlib import Path

ALGORITHM = "ML-KEM-768"
PUBLIC_KEY_BYTES = 1184
SECRET_KEY_BYTES = 2400
CIPHERTEXT_BYTES = 1088
SHARED_SECRET_BYTES = 32
OQS_SUCCESS = 0


def _library_path() -> Path:
    override = os.environ.get("PQ_SHIELD_OQS_LIB")
    if override:
        return Path(override)
    extension = ".dylib" if os.uname().sysname == "Darwin" else ".so"
    local = Path(__file__).parents[1] / "work" / "oqs-prefix" / "lib" / f"liboqs{extension}"
    if local.exists():
        return local
    raise RuntimeError(
        "liboqs was not found. Run scripts/install_oqs.sh or set PQ_SHIELD_OQS_LIB "
        "to the absolute path of liboqs."
    )


class MlKem768:
    """Owns one liboqs ML-KEM object and provides safe byte-oriented methods."""

    def __init__(self) -> None:
        self._lib = ctypes.CDLL(str(_library_path()))
        self._lib.OQS_KEM_new.argtypes = [ctypes.c_char_p]
        self._lib.OQS_KEM_new.restype = ctypes.c_void_p
        self._lib.OQS_KEM_free.argtypes = [ctypes.c_void_p]
        self._lib.OQS_KEM_keypair.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        self._lib.OQS_KEM_keypair.restype = ctypes.c_int
        self._lib.OQS_KEM_encaps.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        self._lib.OQS_KEM_encaps.restype = ctypes.c_int
        self._lib.OQS_KEM_decaps.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        self._lib.OQS_KEM_decaps.restype = ctypes.c_int
        self._kem = self._lib.OQS_KEM_new(ALGORITHM.encode())
        if not self._kem:
            raise RuntimeError(f"liboqs does not have {ALGORITHM} enabled")

    def __del__(self) -> None:
        if getattr(self, "_kem", None):
            self._lib.OQS_KEM_free(self._kem)
            self._kem = None

    @staticmethod
    def _buffer(data: bytes, expected: int):
        if len(data) != expected:
            raise ValueError(f"Expected {expected} bytes, received {len(data)}")
        return (ctypes.c_ubyte * expected).from_buffer_copy(data)

    def generate_keypair(self) -> tuple[bytes, bytes]:
        public_key = (ctypes.c_ubyte * PUBLIC_KEY_BYTES)()
        secret_key = (ctypes.c_ubyte * SECRET_KEY_BYTES)()
        if self._lib.OQS_KEM_keypair(self._kem, public_key, secret_key) != OQS_SUCCESS:
            raise RuntimeError("ML-KEM-768 key generation failed")
        return bytes(public_key), bytes(secret_key)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        ciphertext = (ctypes.c_ubyte * CIPHERTEXT_BYTES)()
        shared_secret = (ctypes.c_ubyte * SHARED_SECRET_BYTES)()
        public = self._buffer(public_key, PUBLIC_KEY_BYTES)
        if self._lib.OQS_KEM_encaps(self._kem, ciphertext, shared_secret, public) != OQS_SUCCESS:
            raise RuntimeError("ML-KEM-768 encapsulation failed")
        return bytes(ciphertext), bytes(shared_secret)

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        shared_secret = (ctypes.c_ubyte * SHARED_SECRET_BYTES)()
        cipher = self._buffer(ciphertext, CIPHERTEXT_BYTES)
        secret = self._buffer(secret_key, SECRET_KEY_BYTES)
        if self._lib.OQS_KEM_decaps(self._kem, shared_secret, cipher, secret) != OQS_SUCCESS:
            raise RuntimeError("ML-KEM-768 decapsulation failed")
        return bytes(shared_secret)

