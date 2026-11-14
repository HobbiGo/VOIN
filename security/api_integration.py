"""
VOIN SECURITY API INTEGRATION ENGINE V1.0

Connects:
- VOIN Security API Engine
- VOIN Security Integration Engine

Features:
- Unified security API access
- Wallet authentication delegation
- API request delegation
- Engine status reporting
"""

from security.api import VOINSecurityAPIEngine


class VOINSecurityAPIIntegration:

    VERSION = "1.0.0"

    def __init__(
        self,
        api_engine,
        security_integration
    ):

        if not isinstance(
            api_engine,
            VOINSecurityAPIEngine
        ):
            raise TypeError(
                "Invalid VOIN Security API Engine"
            )

        if not callable(
            getattr(
                security_integration,
                "verify_authentication",
                None
            )
        ):
            raise TypeError(
                "Invalid VOIN Security Integration Engine"
            )

        self.api_engine = api_engine
        self.security_integration = security_integration

    def handle_api_request(
        self,
        method,
        path,
        headers=None,
        query=None
    ):

        return self.api_engine.handle_request(
            method=method,
            path=path,
            headers=headers,
            query=query
        )

    def verify_wallet_authentication(
        self,
        wallet_address,
        challenge,
        signature,
        nonce
    ):

        return self.security_integration.verify_authentication(
            wallet_address=wallet_address,
            challenge=challenge,
            signature=signature,
            nonce=nonce
        )

    def engine_info(self):

        return {
            "engine": "VOIN Security API Integration",
            "version": self.VERSION,
            "api_engine": True,
            "wallet_authentication": True,
            "security_integration": True,
            "status": "READY_FOR_TESTING"
        }
