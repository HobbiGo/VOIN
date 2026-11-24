"""
VOIN SECURITY ENGINE
Version 1.0.0

Core security package for VOIN on BSC Mainnet (Chain ID 56).
"""

ENGINE_NAME = "VOIN Security Engine"
ENGINE_VERSION = "1.0.0"
DEFAULT_CHAIN_ID = 56
DEFAULT_NETWORK = "BSC_MAINNET"

__all__ = [
    "ENGINE_NAME",
    "ENGINE_VERSION",
    "DEFAULT_CHAIN_ID",
    "DEFAULT_NETWORK",
    "engine_info",
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
]


def engine_info() -> dict:
    """Mengembalikan informasi utama paket VOIN Security Engine."""
    return {
        "engine": ENGINE_NAME,
        "version": ENGINE_VERSION,
        "chain_id": DEFAULT_CHAIN_ID,
        "network": DEFAULT_NETWORK,
        "modules": [
            name for name in __all__
            if name not in {
                "ENGINE_NAME",
                "ENGINE_VERSION",
                "DEFAULT_CHAIN_ID",
                "DEFAULT_NETWORK",
                "engine_info",
            }
        ],
        "status": "MAINNET_READY",
    }
