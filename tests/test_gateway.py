"""
VOIN SECURITY GATEWAY INTEGRATION TESTS V1.2
"""

import pytest

from security.api import VOINSecurityAPIEngine
from security.gateway import VOINSecurityGateway
from security.integration import VOINSecurityIntegration


TEST_TOKEN = "voin-test-api-token-" + ("x" * 40)


def make_dashboard():
    class FakeDashboard:
        def get_dashboard(self):
            return {"status": "OPERATIONAL"}

    return FakeDashboard()


@pytest.fixture
def api_engine():
    return VOINSecurityAPIEngine(
        dashboard=make_dashboard(),
        api_token=TEST_TOKEN
    )


@pytest.fixture
def security_integration():
    return VOINSecurityIntegration()


@pytest.fixture
def gateway(api_engine, security_integration):
    return VOINSecurityGateway(
        api_engine=api_engine,
        security_integration=security_integration,
        host="127.0.0.1",
        port=0
    )


def test_wallet_authentication_delegation(gateway, monkeypatch):
    monkeypatch.setattr(
        gateway.api_integration,
        "create_wallet_authentication",
        lambda wallet_address: {
            "success": True,
            "wallet": wallet_address
        }
    )

    result = gateway.create_wallet_authentication("0x1234")

    assert result == {
        "success": True,
        "wallet": "0x1234"
    }


def test_wallet_verification_delegation(gateway, monkeypatch):
    monkeypatch.setattr(
        gateway.api_integration,
        "verify_wallet_authentication",
        lambda wallet_address, challenge_id, signature: {
            "success": True,
            "wallet": wallet_address,
            "challenge_id": challenge_id
        }
    )

    result = gateway.verify_wallet_authentication(
        wallet_address="0x1234",
        challenge_id="challenge-test",
        signature="signature-test"
    )

    assert result == {
        "success": True,
        "wallet": "0x1234",
        "challenge_id": "challenge-test"
    }


def test_api_request_delegation(gateway, monkeypatch):
    monkeypatch.setattr(
        gateway.api_integration,
        "handle_api_request",
        lambda method, path, headers=None, query=None: {
            "status_code": 200,
            "body": {"success": True}
        }
    )

    result = gateway.handle_api_request(
        "GET",
        "/dashboard"
    )

    assert result == {
        "status_code": 200,
        "body": {"success": True}
    }


def test_wsgi_application_delegation(gateway, monkeypatch):
    monkeypatch.setattr(
        gateway.http_server,
        "application",
        lambda environ, start_response: ["gateway-ok"]
    )

    monkeypatch.setattr(
        gateway.middleware,
        "application",
        gateway.http_server.application
    )

    result = gateway.application(
        {},
        lambda status, headers: None
    )

    assert result == ["gateway-ok"]


def test_gateway_component_versions(gateway):
    info = gateway.engine_info()

    assert info["version"] == "1.1.1"

    assert (
        info["api_integration"]
        == gateway.api_integration.VERSION
    )

    assert (
        info["http_server"]
        == gateway.http_server.VERSION
    )

    assert (
        info["middleware"]
        == gateway.middleware.VERSION
    )
