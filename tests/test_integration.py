"""
VOIN SECURITY INTEGRATION TEST SUITE V1.1.0

Tests:
- Integration engine creation
- Legacy wallet authentication compatibility
- Authentication argument delegation
- API request delegation
- Engine information
- Invalid API engine rejection
- Invalid security integration rejection
"""

import pytest

from security.api import VOINSecurityAPIEngine
from security.api_integration import VOINSecurityAPIIntegration


TEST_TOKEN = "voin-test-api-token-" + ("x" * 40)


class FakeDashboard:

    def __init__(self):
        self.alert_engine = None
        self.monitor_engine = None
        self.rate_limit_engine = None

    def get_dashboard(self):
        return {
            "status": "OPERATIONAL"
        }


class FakeSecurityIntegration:

    def __init__(self):
        self.called = False
        self.last_arguments = None

    def verify_authentication(
        self,
        wallet_address,
        challenge,
        signature,
        nonce
    ):

        self.called = True

        self.last_arguments = {
            "wallet_address": wallet_address,
            "challenge": challenge,
            "signature": signature,
            "nonce": nonce
        }

        return {
            "success": True,
            "status": "AUTHENTICATED"
        }


@pytest.fixture
def api_engine():

    return VOINSecurityAPIEngine(
        dashboard=FakeDashboard(),
        api_token=TEST_TOKEN
    )


@pytest.fixture
def security_integration():

    return FakeSecurityIntegration()


@pytest.fixture
def integration(
    api_engine,
    security_integration
):

    return VOINSecurityAPIIntegration(
        api_engine=api_engine,
        security_integration=security_integration
    )


def test_integration_engine_creation(integration):

    assert integration.VERSION == "1.1.0"


def test_legacy_wallet_authentication(
    integration,
    security_integration
):

    wallet_address = "0x1234567890abcdef"
    challenge = "test-challenge"
    signature = "test-signature"
    nonce = "test-nonce"

    response = integration.verify_wallet_authentication(
        wallet_address=wallet_address,
        challenge=challenge,
        signature=signature,
        nonce=nonce
    )

    assert response["success"] is True
    assert response["status"] == "AUTHENTICATED"

    assert security_integration.called is True

    assert security_integration.last_arguments == {
        "wallet_address": wallet_address,
        "challenge": challenge,
        "signature": signature,
        "nonce": nonce
    }


def test_api_request_delegation(integration):

    response = integration.handle_api_request(
        method="GET",
        path="/api/security/dashboard",
        headers={
            "Authorization": f"Bearer {TEST_TOKEN}"
        }
    )

    assert response.status_code == 200
    assert response.body["success"] is True
    assert response.body["data"]["status"] == "OPERATIONAL"


def test_engine_info(integration):

    info = integration.engine_info()

    assert info["engine"] == "VOIN Security API Integration"
    assert info["version"] == "1.1.0"
    assert info["api_engine"] is True
    assert info["wallet_authentication"] is True
    assert info["challenge_creation"] is False
    assert info["challenge_id_verification"] is True
    assert info["persistent_nonce_compatibility"] is True
    assert info["security_integration"] is True
    assert info["status"] == "READY_FOR_TESTING"


def test_invalid_api_engine(security_integration):

    with pytest.raises(TypeError):

        VOINSecurityAPIIntegration(
            api_engine=object(),
            security_integration=security_integration
        )


def test_invalid_security_integration(api_engine):

    with pytest.raises(TypeError):

        VOINSecurityAPIIntegration(
            api_engine=api_engine,
            security_integration=object()
        )
