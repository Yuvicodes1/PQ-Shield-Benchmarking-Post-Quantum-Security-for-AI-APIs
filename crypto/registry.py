"""Central lookup from configuration name -> (ServerCryptoConfig, ClientCryptoConfig) classes.

Used by api/server_config_*.py, bench/runner.py, and threats/*.py so that
"classical" / "hybrid" / "full_pqc" is the single string that selects a
configuration everywhere in the project.
"""

from __future__ import annotations

from .classical import ClassicalClientCrypto, ClassicalServerCrypto
from .full_pqc import FullPQCClientCrypto, FullPQCServerCrypto
from .hybrid import HybridClientCrypto, HybridServerCrypto

CONFIGS = {
    "classical": (ClassicalServerCrypto, ClassicalClientCrypto),
    "hybrid": (HybridServerCrypto, HybridClientCrypto),
    "full_pqc": (FullPQCServerCrypto, FullPQCClientCrypto),
}

CONFIG_NAMES = list(CONFIGS.keys())


def get_server_crypto(config_name: str):
    server_cls, _ = CONFIGS[config_name]
    return server_cls()


def get_client_crypto(config_name: str):
    _, client_cls = CONFIGS[config_name]
    return client_cls()
