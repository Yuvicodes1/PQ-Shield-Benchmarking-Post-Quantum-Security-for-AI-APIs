"""Central lookup from payload-profile name -> PayloadProfile instance.

Selection is driven by the PQ_SHIELD_PAYLOAD_PROFILE environment variable
(default: tabular_small), read fresh on every get_profile() call -- not
cached at import time -- so setting the env var any time before the first
call (e.g. a CLI script setting it right after argparse, before importing
anything else) is sufficient; there is no import-order requirement here
unlike crypto/oqs_adapter.py's liboqs library load.

Every server process picks its active profile exactly once, from this
environment variable, at first use (api/model_service.py calls
get_profile() with no argument). bench/orchestrator.py and
bench/payload_sensitivity.py set this variable in each server subprocess's
environment before starting it, so client and server always agree on
which profile is active without it needing to travel over the wire.
"""

from __future__ import annotations

import os

from .base import PayloadProfile
from .embedding import EmbeddingProfile
from .image_cnn import ImageCNNProfile
from .llm_completion import LLMCompletionProfile
from .tabular_small import TabularSmallProfile

PROFILE_CLASSES = {
    "tabular_small": TabularSmallProfile,
    "image_cnn": ImageCNNProfile,
    "embedding": EmbeddingProfile,
    "llm_completion": LLMCompletionProfile,
}
PROFILE_NAMES = list(PROFILE_CLASSES.keys())
DEFAULT_PROFILE = "tabular_small"

_instances: dict[str, PayloadProfile] = {}


def get_profile(name: str | None = None) -> PayloadProfile:
    name = name or os.environ.get("PQ_SHIELD_PAYLOAD_PROFILE", DEFAULT_PROFILE)
    if name not in PROFILE_CLASSES:
        raise ValueError(f"Unknown payload profile '{name}'. Valid options: {PROFILE_NAMES}")
    if name not in _instances:
        _instances[name] = PROFILE_CLASSES[name]()
    return _instances[name]
