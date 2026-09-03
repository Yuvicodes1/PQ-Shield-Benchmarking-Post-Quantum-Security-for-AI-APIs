"""Thin dispatcher to the active payload profile (model/profiles/*),
selected once per process via the PQ_SHIELD_PAYLOAD_PROFILE environment
variable (default: tabular_small). Every server (control + Configs A/B/C)
imports this module rather than a profile directly, so swapping which AI
workload is being benchmarked is one environment variable, not a code
change to the server or the protocol layer.
"""

from __future__ import annotations

from model.profiles.registry import get_profile


def predict(request_body: dict) -> dict:
    return get_profile().predict(request_body)


def sample_request() -> dict:
    return get_profile().sample_request()


def warm_up() -> None:
    predict(sample_request())


def active_profile_name() -> str:
    return get_profile().name


def active_profile_description() -> str:
    return get_profile().description


def active_profile_real_inference() -> bool:
    return get_profile().real_inference
