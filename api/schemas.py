"""Pydantic models for the protected handshake/predict envelope shared by
Configurations A/B/C. The control server's /predict accepts a generic JSON
body directly (api/server.py) since its shape varies by payload profile
(model/profiles/*) -- only the encrypted envelope below has a fixed shape,
because it carries opaque bytes regardless of which profile produced them.
"""

from __future__ import annotations

from pydantic import BaseModel


class HandshakeResponse(BaseModel):
    handshake_id: str
    kex_public_key: str  # base64
    sig_public_key: str  # base64
    kex_algorithm: str
    sig_algorithm: str
    meta: dict


class SecurePredictRequest(BaseModel):
    handshake_id: str
    # base64 kex blob (RSA-OAEP ct / X25519 share / ML-KEM ct) that establishes the session key.
    # Empty on a resumed request: the server reuses the session key it cached under handshake_id.
    kex_blob: str = ""
    nonce: str  # base64 -- AES-GCM nonce for the request payload
    ciphertext: str  # base64 -- AES-GCM ciphertext of the request JSON body
    # Ask the server to keep this handshake's session key (and signing key) for further
    # requests -- session resumption, as a TLS deployment reusing a connection would.
    # The last request of a session sends False and the server forgets everything.
    keep_session: bool = False


class SecurePredictResponse(BaseModel):
    nonce: str  # base64 -- AES-GCM nonce for the response payload
    ciphertext: str  # base64 -- AES-GCM ciphertext of the response JSON body
    signature: str  # base64 -- signature over (nonce || ciphertext)
    server_timing_ms: dict  # decapsulate_ms, inference_ms, encrypt_ms, sign_ms, total_ms -- always included, non-sensitive
    debug: dict | None = None  # byte-size breakdown, only when X-Debug-Metrics: true is sent
