"""
VOIN SECURITY ENGINE
Version 1.0.0

Core security package for VOIN on BSC Mainnet (Chain ID 56).
"""

import importlib

ENGINE_NAME = "VOIN Security Engine"
ENGINE_VERSION = "1.0.0"
DEFAULT_CHAIN_ID = 56
DEFAULT_NETWORK = "BSC_MAINNET"

_SUBMODULES = (
    "alert",
    "challenge",
    "monitor",
    "network",
    "nonce",
    "pqc_signer",
    "quantum",
    "rate_limit",
    "security_api",
    "signatures",
    "storage",
    "threat_detection",
    "transaction",
    "transport",
    "verification",
    "wallet",
)

__all__ = [
    "ENGINE_NAME",
    "ENGINE_VERSION",
    "DEFAULT_CHAIN_ID",
    "DEFAULT_NETWORK",
    "engine_info",
    *_SUBMODULES,
]


def __getattr__(name: str):
    if name in _SUBMODULES:
        module = importlib.import_module(f"{__name__}.{name}")
        globals()[name] = module
        return module
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


def __dir__():
    return sorted(set(globals()) | set(__all__))


def engine_info() -> dict:
    """Mengembalikan informasi utama paket VOIN Security Engine."""
    return {
        "engine": ENGINE_NAME,
        "version": ENGINE_VERSION,
        "chain_id": DEFAULT_CHAIN_ID,
        "network": DEFAULT_NETWORK,
        "modules": list(_SUBMODULES),
        "status": "MAINNET_READY",
    }
