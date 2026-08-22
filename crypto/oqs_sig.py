"""Minimal ctypes adapter for liboqs ML-DSA-65 signatures."""

import ctypes
from typing import Optional

from crypto.oqs_kem import OQS_SUCCESS, _library_path

ALGORITHM = "ML-DSA-65"
PUBLIC_KEY_BYTES = 1952
SECRET_KEY_BYTES = 4032
SIGNATURE_BYTES = 3309


class MlDsa65:
    """Owns one liboqs ML-DSA-65 object and exposes byte-oriented operations."""

    def __init__(self) -> None:
        self._lib = ctypes.CDLL(str(_library_path()))
        self._lib.OQS_SIG_new.argtypes = [ctypes.c_char_p]
        self._lib.OQS_SIG_new.restype = ctypes.c_void_p
        self._lib.OQS_SIG_free.argtypes = [ctypes.c_void_p]
        self._lib.OQS_SIG_keypair.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        self._lib.OQS_SIG_keypair.restype = ctypes.c_int
        self._lib.OQS_SIG_sign.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p,
            ctypes.c_size_t, ctypes.c_void_p,
        ]
        self._lib.OQS_SIG_sign.restype = ctypes.c_int
        self._lib.OQS_SIG_verify.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_void_p,
        ]
        self._lib.OQS_SIG_verify.restype = ctypes.c_int
        self._sig = self._lib.OQS_SIG_new(ALGORITHM.encode())
        if not self._sig:
            raise RuntimeError(f"liboqs does not have {ALGORITHM} enabled")

    def __del__(self) -> None:
        if getattr(self, "_sig", None):
            self._lib.OQS_SIG_free(self._sig)
            self._sig = None

    @staticmethod
    def _buffer(data: bytes, expected: Optional[int] = None):
        if expected is not None and len(data) != expected:
            raise ValueError(f"Expected {expected} bytes, received {len(data)}")
        return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)

    def generate_keypair(self) -> tuple[bytes, bytes]:
        public_key = (ctypes.c_ubyte * PUBLIC_KEY_BYTES)()
        secret_key = (ctypes.c_ubyte * SECRET_KEY_BYTES)()
        if self._lib.OQS_SIG_keypair(self._sig, public_key, secret_key) != OQS_SUCCESS:
            raise RuntimeError("ML-DSA-65 key generation failed")
        return bytes(public_key), bytes(secret_key)

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        secret = self._buffer(secret_key, SECRET_KEY_BYTES)
        signed_message = self._buffer(message)
        signature = (ctypes.c_ubyte * SIGNATURE_BYTES)()
        signature_length = ctypes.c_size_t(SIGNATURE_BYTES)
        if self._lib.OQS_SIG_sign(
            self._sig, signature, ctypes.byref(signature_length), signed_message, len(message), secret
        ) != OQS_SUCCESS:
            raise RuntimeError("ML-DSA-65 signing failed")
        return bytes(signature[:signature_length.value])

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        public = self._buffer(public_key, PUBLIC_KEY_BYTES)
        signed_message = self._buffer(message)
        signed = self._buffer(signature)
        return self._lib.OQS_SIG_verify(
            self._sig, signed_message, len(message), signed, len(signature), public
        ) == OQS_SUCCESS
