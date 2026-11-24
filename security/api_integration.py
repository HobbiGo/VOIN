"""
VOIN SECURITY API INTEGRATION ENGINE V1.1.0

Features:
- Security API delegation
- Wallet authentication creation
- Wallet authentication verification
- Challenge ID support
- Legacy authentication compatibility
- Engine validation
- Engine status reporting
"""

import inspect
import re

from security.api import VOINSecurityAPIEngine

DEFAULT_CHAIN_ID = 56
_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ZERO_ADDRESS = "0x" + ("0" * 40)


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

    @staticmethod
    def _normalize_wallet(wallet_address, *, allow_zero: bool = False) -> str:
        if not isinstance(wallet_address, str):
            raise ValueError("Invalid wallet address")

        cleaned = wallet_address.strip()
        if not cleaned:
            raise ValueError("Invalid wallet address")

        if not _EVM_ADDRESS_RE.match(cleaned):
            raise ValueError("Invalid EVM wallet address format")

        normalized = cleaned.lower()
        if not allow_zero and normalized == _ZERO_ADDRESS:
            raise ValueError("Zero address is not allowed")

        return normalized

    @staticmethod
    def _clean_optional_str(value):
        if isinstance(value, str):
            cleaned = value.strip()
            return cleaned if cleaned else None
        return value

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

        normalized_wallet = self._normalize_wallet(wallet_address)

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
            wallet_address=normalized_wallet
        )

    def verify_wallet_authentication(
        self,
        wallet_address,
        challenge=None,
        signature=None,
        nonce=None,
        challenge_id=None
    ):

        normalized_wallet = self._normalize_wallet(wallet_address)
        cleaned_challenge = self._clean_optional_str(challenge)
        cleaned_challenge_id = self._clean_optional_str(challenge_id)
        cleaned_nonce = nonce.strip() if isinstance(nonce, str) else nonce

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
                wallet_address=normalized_wallet,
                challenge=cleaned_challenge,
                signature=signature,
                nonce=cleaned_nonce
            )

        resolved_challenge_id = (
            cleaned_challenge_id
            if cleaned_challenge_id is not None
            else cleaned_challenge
        )

        return verify_method(
            challenge_id=resolved_challenge_id,
            wallet_address=normalized_wallet,
            signature=signature
        )

    def engine_info(self):

        return {
            "engine": "VOIN Security API Integration",
            "version": self.VERSION,
            "chain_id": DEFAULT_CHAIN_ID,
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
            "status": "MAINNET_READY"
        }
