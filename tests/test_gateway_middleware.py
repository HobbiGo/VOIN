"""
VOIN SECURITY GATEWAY MIDDLEWARE TEST SUITE V1.0
"""

import json
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


def invoke(gateway, environ):
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = dict(headers)

    response = gateway.application(
        environ,
        start_response
    )

    body = b"".join(response)

    return body, captured, environ


def mock_api(gateway, monkeypatch, response=None, error=None):

    def handler(**kwargs):
        if error is not None:
            raise error

        return response or {
            "status_code": 200,
            "body": {"success": True}
        }

    monkeypatch.setattr(
        gateway.http_server.api_integration,
        "handle_api_request",
        handler
    )


def test_gateway_middleware_enabled(gateway):

    assert gateway.middleware is not None

    assert gateway.middleware.VERSION == "1.0.0"

    assert gateway.engine_info()["middleware_enabled"] is True


def test_gateway_middleware_valid_request(
    gateway,
    monkeypatch
):

    mock_api(gateway, monkeypatch)

    result = invoke(
        gateway,
        {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/dashboard"
        }
    )

    body, captured, environ = result

    assert captured["status"] == "200 OK"

    assert json.loads(body) == {
        "success": True
    }


def test_gateway_middleware_request_id(
    gateway,
    monkeypatch
):

    mock_api(gateway, monkeypatch)

    result = invoke(
        gateway,
        {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/dashboard"
        }
    )

    body, captured, environ = result

    assert "voin.request_id" in environ

    request_id = environ["voin.request_id"]

    assert len(request_id) == 32

    assert (
        captured["headers"]["X-Request-ID"]
        == request_id
    )


def test_gateway_middleware_security_headers(
    gateway,
    monkeypatch
):

    mock_api(gateway, monkeypatch)

    result = invoke(
        gateway,
        {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/dashboard"
        }
    )

    body, captured, environ = result

    headers = captured["headers"]

    assert headers["X-Content-Type-Options"] == "nosniff"

    assert headers["X-Frame-Options"] == "DENY"

    assert headers["Cache-Control"] == "no-store"

    assert headers["Referrer-Policy"] == "no-referrer"


def test_gateway_middleware_rejects_invalid_path(gateway):

    result = invoke(
        gateway,
        {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "invalid-path"
        }
    )

    body, captured, environ = result

    assert captured["status"] == "400 Bad Request"

    response = json.loads(body)

    assert response["error"] == "Invalid request"


def test_gateway_middleware_handles_internal_error(
    gateway,
    monkeypatch
):

    mock_api(
        gateway,
        monkeypatch,
        error=RuntimeError("test error")
    )

    result = invoke(
        gateway,
        {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/dashboard"
        }
    )

    body, captured, environ = result

    assert captured["status"] == "500 Internal Server Error"

    response = json.loads(body)

    assert response["error"] == "Internal server error"
