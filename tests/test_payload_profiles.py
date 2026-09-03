"""Tests for model/profiles/*: every profile must produce a valid
request/response round trip, and the response must include a numeric
'_inference_ms'. Byte-size assertions pin down the "small vs large"
request/response claims this project's payload-sensitivity study depends
on -- if a profile's payload shape drifts, these tests catch it before it
silently invalidates a figure.
"""

import json

import pytest

from model.profiles.registry import PROFILE_NAMES, get_profile


@pytest.mark.parametrize("profile_name", PROFILE_NAMES)
def test_profile_roundtrip(profile_name):
    profile = get_profile(profile_name)
    request_body = profile.sample_request()
    assert isinstance(request_body, dict)

    response_body = profile.predict(request_body)
    assert isinstance(response_body, dict)
    assert "_inference_ms" in response_body
    assert isinstance(response_body["_inference_ms"], (int, float))
    assert response_body["_inference_ms"] >= 0

    # Every profile's request/response must be JSON-serializable, since it
    # travels as the AEAD plaintext over the wire.
    json.dumps(request_body)
    json.dumps({k: v for k, v in response_body.items() if k != "_inference_ms"})


def test_tabular_small_shape():
    profile = get_profile("tabular_small")
    req = profile.sample_request()
    assert len(req["input"]) == 64
    resp = profile.predict(req)
    assert 0 <= resp["prediction"] <= 9
    assert len(resp["probabilities"]) == 10
    assert abs(sum(resp["probabilities"]) - 1.0) < 1e-6

    request_bytes = len(json.dumps(req).encode())
    assert 200 < request_bytes < 600, f"tabular_small request should be ~small, got {request_bytes}B"


def test_image_cnn_shape():
    profile = get_profile("image_cnn")
    req = profile.sample_request()
    assert "image_base64" in req
    resp = profile.predict(req)
    assert 0 <= resp["prediction"] <= 9
    assert len(resp["probabilities"]) == 10
    assert abs(sum(resp["probabilities"]) - 1.0) < 1e-4

    request_bytes = len(json.dumps(req).encode())
    tabular_bytes = len(json.dumps(get_profile("tabular_small").sample_request()).encode())
    assert request_bytes > tabular_bytes * 5, (
        f"image_cnn request ({request_bytes}B) should be much larger than "
        f"tabular_small's ({tabular_bytes}B)"
    )


def test_image_cnn_deterministic_weights():
    """Same profile instance must give identical output for identical input
    -- weights must not be re-randomized per call."""
    profile = get_profile("image_cnn")
    req = profile.sample_request()
    resp1 = profile.predict(req)
    resp2 = profile.predict(req)
    assert resp1["prediction"] == resp2["prediction"]
    assert resp1["probabilities"] == resp2["probabilities"]


def test_embedding_shape():
    profile = get_profile("embedding")
    req = profile.sample_request()
    assert "text" in req
    resp = profile.predict(req)
    assert resp["dim"] == 768
    assert len(resp["embedding"]) == 768

    response_bytes = len(json.dumps({k: v for k, v in resp.items() if k != "_inference_ms"}).encode())
    assert response_bytes > 2000, f"embedding response should be large, got {response_bytes}B"


def test_embedding_deterministic():
    """Same text must always produce the same embedding (seeded from a hash of the text)."""
    profile = get_profile("embedding")
    resp1 = profile.predict({"text": "a fixed test sentence"})
    resp2 = profile.predict({"text": "a fixed test sentence"})
    assert resp1["embedding"] == resp2["embedding"]

    resp3 = profile.predict({"text": "a different test sentence"})
    assert resp3["embedding"] != resp1["embedding"]


def test_llm_completion_shape():
    profile = get_profile("llm_completion")
    req = profile.sample_request()
    assert "prompt" in req
    resp = profile.predict(req)
    assert "completion" in resp
    assert resp["tokens_generated"] > 0

    response_bytes = len(json.dumps({k: v for k, v in resp.items() if k != "_inference_ms"}).encode())
    request_bytes = len(json.dumps(req).encode())
    assert response_bytes > request_bytes * 2, (
        "llm_completion response should be substantially larger than its request "
        f"(request={request_bytes}B, response={response_bytes}B)"
    )


def test_llm_completion_deterministic():
    profile = get_profile("llm_completion")
    resp1 = profile.predict({"prompt": "test prompt", "max_tokens": 100})
    resp2 = profile.predict({"prompt": "test prompt", "max_tokens": 100})
    assert resp1["completion"] == resp2["completion"]


def test_registry_rejects_unknown_profile():
    with pytest.raises(ValueError):
        get_profile("not_a_real_profile")
