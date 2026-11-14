"""
VOIN SECURITY API INTEGRATION ENGINE V1.1

Connects:
- VOIN Security API Engine
- VOIN Security Integration Engine

Features:
- Unified security API access
- Wallet authentication creation
- Wallet authentication verification
- Challenge ID support
- Legacy challenge and nonce compatibility
- API request delegation
- Engine status reporting
"""

import inspect

from security.api import VOINSecurityAPIEngine


class VOINSecurityAPIIntegration:

    VERSION = "1.1.0"

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

    def create_wallet_authentication(
        self,
        wallet_address
    ):

        create_method = getattr(
            self.security_integration,
            "create_authentication",
            None
        )

        if not callable(create_method):
            raise TypeError(
                "Security Integration does not support challenge creation"
            )

        return create_method(
            wallet_address=wallet_address
        )

    def verify_wallet_authentication(
        self,
        wallet_address,
        challenge=None,
        signature=None,
        nonce=None,
        challenge_id=None
    ):

        verify_method = (
            self.security_integration.verify_authentication
        )

        parameters = inspect.signature(
            verify_method
        ).parameters

        supports_legacy = (
            "challenge" in parameters
            and "nonce" in parameters
        )

        if supports_legacy:

            return verify_method(
                wallet_address=wallet_address,
                challenge=challenge,
                signature=signature,
                nonce=nonce
            )

        if challenge_id is None:
            challenge_id = challenge

        return verify_method(
            challenge_id=challenge_id,
            wallet_address=wallet_address,
            signature=signature
        )

    def engine_info(self):

        return {
            "engine": "VOIN Security API Integration",
            "version": self.VERSION,
            "api_engine": True,
            "wallet_authentication": True,
            "challenge_creation": callable(
                getattr(
                    self.security_integration,
                    "create_authentication",
                    None
                )
            ),
            "challenge_id_verification": True,
            "persistent_nonce_compatibility": True,
            "security_integration": True,
            "status": "READY_FOR_TESTING"
        }
