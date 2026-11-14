"""
VOIN SECURITY API INTEGRATION TEST SUITE V1.1
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

    def create_authentication(self, wallet_address):

        self.called = True

        self.last_arguments = {
            "wallet_address": wallet_address
        }

        return {
            "success": True,
            "status": "AUTHENTICATION_CHALLENGE_CREATED"
        }

    def verify_authentication(
        self,
        challenge_id,
        wallet_address,
        signature
    ):

        self.called = True

        self.last_arguments = {
            "challenge_id": challenge_id,
            "wallet_address": wallet_address,
            "signature": signature
        }

        return {
            "success": True,
            "status": "AUTHENTICATION_SUCCESSFUL"
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

    assert info["version"] == "1.1.0"


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


def test_wallet_authentication_creation(
    integration,
    security_integration
):

    result = integration.create_wallet_authentication(
        wallet_address="0x1234567890"
    )

    assert result["success"] is True
    assert security_integration.called is True

    assert security_integration.last_arguments == {
        "wallet_address": "0x1234567890"
    }


def test_wallet_authentication_verification(
    integration,
    security_integration
):

    result = integration.verify_wallet_authentication(
        wallet_address="0x1234567890",
        challenge_id="challenge-001",
        signature="test-signature"
    )

    assert result["success"] is True

    assert result["status"] == "AUTHENTICATION_SUCCESSFUL"

    assert security_integration.called is True


def test_wallet_authentication_arguments(
    integration,
    security_integration
):

    integration.verify_wallet_authentication(
        wallet_address="0x1234567890",
        challenge_id="challenge-001",
        signature="signature-001"
    )

    assert security_integration.last_arguments == {
        "challenge_id": "challenge-001",
        "wallet_address": "0x1234567890",
        "signature": "signature-001"
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

    assert info["version"] == "1.1.0"
    assert info["api_engine"] is True
    assert info["wallet_authentication"] is True
    assert info["challenge_creation"] is True
    assert info["challenge_id_verification"] is True
    assert info["security_integration"] is True
    assert info["status"] == "READY_FOR_TESTING"
