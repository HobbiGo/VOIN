"""
VOIN SECURITY API INTEGRATION TEST SUITE V1.0

Tests:
- API integration creation
- API request delegation
- Wallet authentication delegation
- Invalid engine rejection
- Engine information
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
def integration(api_engine, security_integration):

    return VOINSecurityAPIIntegration(
        api_engine=api_engine,
        security_integration=security_integration
    )


def test_integration_engine_creation(integration):

    assert integration.VERSION == "1.0.0"


def test_api_request_delegation(integration):

    response = integration.handle_api_request(
        method="GET",
        path="/api/security/dashboard",
        headers={
            "Authorization": f"Bearer {TEST_TOKEN}"
        }
    )

    assert response["status_code"] == 200
    assert response["body"]["success"] is True
    assert response["body"]["data"]["status"] == "OPERATIONAL"


def test_unauthorized_api_request(integration):

    response = integration.handle_api_request(
        method="GET",
        path="/api/security/dashboard"
    )

    assert response["status_code"] == 401


def test_wallet_authentication_delegation(
    integration,
    security_integration
):

    result = integration.verify_wallet_authentication(
        wallet_address="0x1234567890",
        challenge="test-challenge",
        signature="test-signature",
        nonce="test-nonce"
    )

    assert result["success"] is True
    assert result["status"] == "AUTHENTICATED"

    assert security_integration.called is True


def test_wallet_authentication_arguments(
    integration,
    security_integration
):

    integration.verify_wallet_authentication(
        wallet_address="0x1234567890",
        challenge="challenge-1",
        signature="signature-1",
        nonce="nonce-1"
    )

    assert security_integration.last_arguments == {
        "wallet_address": "0x1234567890",
        "challenge": "challenge-1",
        "signature": "signature-1",
        "nonce": "nonce-1"
    }


def test_invalid_api_engine_rejected():

    with pytest.raises(TypeError):

        VOINSecurityAPIIntegration(
            api_engine=object(),
            security_integration=FakeSecurityIntegration()
        )


def test_invalid_security_integration_rejected(api_engine):

    with pytest.raises(TypeError):

        VOINSecurityAPIIntegration(
            api_engine=api_engine,
            security_integration=object()
        )


def test_engine_info(integration):

    info = integration.engine_info()

    assert info["version"] == "1.0.0"
    assert info["api_engine"] is True
    assert info["wallet_authentication"] is True
    assert info["security_integration"] is True
    assert info["status"] == "READY_FOR_TESTING"
