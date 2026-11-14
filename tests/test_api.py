"""
VOIN SECURITY API TEST SUITE V1.0

Tests:
- Bearer token authentication
- Protected API endpoints
- Dashboard access
- Alert access
- Monitoring access
- Rate-limit status access
- Invalid request handling
- Read-only restrictions
"""

import pytest

from security.api import VOINSecurityAPIEngine


TEST_TOKEN = "voin-test-api-token-" + ("x" * 40)


class FakeAlertEngine:

    def get_alerts(self, limit=100):
        return [
            {
                "id": 1,
                "risk_level": "HIGH"
            }
        ][:limit]


class FakeMonitorEngine:

    def get_security_status(self):
        return {
            "status": "NORMAL"
        }


class FakeRateLimitEngine:

    def get_status(self, wallet_address):
        return {
            "wallet_address": wallet_address,
            "status": "ACTIVE"
        }


class FakeDashboard:

    def __init__(self):
        self.alert_engine = FakeAlertEngine()
        self.monitor_engine = FakeMonitorEngine()
        self.rate_limit_engine = FakeRateLimitEngine()

    def get_dashboard(self):
        return {
            "status": "OPERATIONAL"
        }


@pytest.fixture
def api():

    dashboard = FakeDashboard()

    return VOINSecurityAPIEngine(
        dashboard=dashboard,
        api_token=TEST_TOKEN
    )


@pytest.fixture
def headers():

    return {
        "Authorization": f"Bearer {TEST_TOKEN}"
    }


def test_api_engine_creation(api):

    assert api.VERSION == "1.0.0"


def test_api_token_minimum_length():

    with pytest.raises(ValueError):

        VOINSecurityAPIEngine(
            dashboard=FakeDashboard(),
            api_token="short"
        )


def test_unauthorized_request(api):

    response = api.handle_request(
        "GET",
        "/api/security/dashboard"
    )

    assert response["status_code"] == 401


def test_invalid_bearer_token(api):

    response = api.handle_request(
        "GET",
        "/api/security/dashboard",
        headers={
            "Authorization": "Bearer invalid-token"
        }
    )

    assert response["status_code"] == 401


def test_bearer_authentication_case_insensitive(api):

    response = api.handle_request(
        "GET",
        "/api/security/dashboard",
        headers={
            "authorization": f"bearer {TEST_TOKEN}"
        }
    )

    assert response["status_code"] == 200


def test_dashboard_endpoint(api, headers):

    response = api.handle_request(
        "GET",
        "/api/security/dashboard",
        headers=headers
    )

    assert response["status_code"] == 200
    assert response["body"]["success"] is True
    assert response["body"]["data"]["status"] == "OPERATIONAL"


def test_alert_endpoint(api, headers):

    response = api.handle_request(
        "GET",
        "/api/security/alerts",
        headers=headers
    )

    assert response["status_code"] == 200
    assert len(response["body"]["data"]["alerts"]) == 1


def test_monitoring_endpoint(api, headers):

    response = api.handle_request(
        "GET",
        "/api/security/monitoring",
        headers=headers
    )

    assert response["status_code"] == 200
    assert response["body"]["data"]["status"] == "NORMAL"


def test_rate_limit_endpoint(api, headers):

    response = api.handle_request(
        "GET",
        "/api/security/rate-limit",
        headers=headers,
        query={
            "wallet_address": "0x1234567890"
        }
    )

    assert response["status_code"] == 200
    assert response["body"]["data"]["status"] == "ACTIVE"


def test_missing_wallet_address(api, headers):

    response = api.handle_request(
        "GET",
        "/api/security/rate-limit",
        headers=headers
    )

    assert response["status_code"] == 400


def test_invalid_alert_limit(api, headers):

    response = api.handle_request(
        "GET",
        "/api/security/alerts",
        headers=headers,
        query={
            "limit": 0
        }
    )

    assert response["status_code"] == 400


def test_alert_limit_boolean_rejected(api, headers):

    response = api.handle_request(
        "GET",
        "/api/security/alerts",
        headers=headers,
        query={
            "limit": True
        }
    )

    assert response["status_code"] == 400


def test_unknown_endpoint(api, headers):

    response = api.handle_request(
        "GET",
        "/api/security/unknown",
        headers=headers
    )

    assert response["status_code"] == 404


def test_post_method_rejected(api, headers):

    response = api.handle_request(
        "POST",
        "/api/security/dashboard",
        headers=headers
    )

    assert response["status_code"] == 405


def test_invalid_method_type(api):

    response = api.handle_request(
        123,
        "/api/security/dashboard"
    )

    assert response["status_code"] == 400


def test_invalid_path_type(api, headers):

    response = api.handle_request(
        "GET",
        123,
        headers=headers
    )

    assert response["status_code"] == 400


def test_invalid_query_type(api, headers):

    response = api.handle_request(
        "GET",
        "/api/security/dashboard",
        headers=headers,
        query=[]
    )

    assert response["status_code"] == 400


def test_engine_info():

    info = VOINSecurityAPIEngine.engine_info()

    assert info["version"] == "1.0.0"
    assert info["bearer_authentication"] is True
    assert info["read_only"] is True
    assert info["status"] == "READY_FOR_TESTING"


def test_internal_error_is_hidden(headers):

    dashboard = FakeDashboard()

    def failing_dashboard():
        raise RuntimeError("Internal test error")

    dashboard.get_dashboard = failing_dashboard

    api = VOINSecurityAPIEngine(
        dashboard=dashboard,
        api_token=TEST_TOKEN
    )

    response = api.handle_request(
        "GET",
        "/api/security/dashboard",
        headers=headers
    )

    assert response["status_code"] == 500
    assert response["body"]["error"] == "Internal server error"
