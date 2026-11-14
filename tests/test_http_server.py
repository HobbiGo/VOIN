"""
VOIN SECURITY HTTP SERVER TEST SUITE V1.0

Tests:
- HTTP server initialization
- WSGI application
- JSON responses
- Bearer authentication delegation
- Query parameter handling
- HTTP status codes
- Security headers
- Server configuration validation
- Engine information
"""

import io
import json

import pytest

from security.http_server import VOINSecurityHTTPServer


TEST_TOKEN = "voin-test-api-token-" + ("x" * 40)


class FakeAPIIntegration:

    def __init__(self):
        self.last_request = None

    def handle_api_request(
        self,
        method,
        path,
        headers=None,
        query=None
    ):

        self.last_request = {
            "method": method,
            "path": path,
            "headers": headers,
            "query": query
        }

        if not headers or headers.get("Authorization") != (
            f"Bearer {TEST_TOKEN}"
        ):
            return {
                "status_code": 401,
                "body": {"error": "Unauthorized"}
            }

        if method != "GET":
            return {
                "status_code": 405,
                "body": {"error": "Method not allowed"}
            }

        if path == "/api/security/dashboard":
            return {
                "status_code": 200,
                "body": {
                    "success": True,
                    "data": {
                        "status": "OPERATIONAL"
                    }
                }
            }

        if path == "/api/security/alerts":
            return {
                "status_code": 200,
                "body": {
                    "success": True,
                    "data": {
                        "limit": query.get("limit", 100)
                    }
                }
            }

        return {
            "status_code": 404,
            "body": {"error": "API endpoint not found"}
        }


@pytest.fixture
def api_integration():

    return FakeAPIIntegration()


@pytest.fixture
def http_server(api_integration):

    return VOINSecurityHTTPServer(
        api_integration=api_integration
    )


def invoke_wsgi(
    application,
    path="/api/security/dashboard",
    method="GET",
    query_string="",
    authorization=None
):

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query_string,
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "8080",
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "http",
        "wsgi.input": io.BytesIO(b""),
        "wsgi.errors": io.StringIO(),
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False
    }

    if authorization is not None:
        environ["HTTP_AUTHORIZATION"] = authorization

    captured = {}

    def start_response(status, headers):

        captured["status"] = status
        captured["headers"] = dict(headers)

    result = application(environ, start_response)

    body = b"".join(result)

    return captured, json.loads(body.decode("utf-8"))


def test_http_server_creation(http_server):

    assert http_server.VERSION == "1.0.0"
    assert http_server.host == "127.0.0.1"
    assert http_server.port == 8080


def test_invalid_api_integration():

    with pytest.raises(TypeError):

        VOINSecurityHTTPServer(
            api_integration=object()
        )


def test_invalid_host(api_integration):

    with pytest.raises(ValueError):

        VOINSecurityHTTPServer(
            api_integration=api_integration,
            host=""
        )


@pytest.mark.parametrize(
    "port",
    [0, -1, 65536, True, "8080"]
)
def test_invalid_port(api_integration, port):

    with pytest.raises(ValueError):

        VOINSecurityHTTPServer(
            api_integration=api_integration,
            port=port
        )


def test_dashboard_wsgi_endpoint(http_server):

    captured, body = invoke_wsgi(
        http_server.application,
        authorization=f"Bearer {TEST_TOKEN}"
    )

    assert captured["status"] == "200 OK"
    assert body["success"] is True
    assert body["data"]["status"] == "OPERATIONAL"


def test_unauthorized_request(http_server):

    captured, body = invoke_wsgi(
        http_server.application
    )

    assert captured["status"] == "401 Unauthorized"
    assert body["error"] == "Unauthorized"


def test_alert_query_parameter(http_server, api_integration):

    captured, body = invoke_wsgi(
        http_server.application,
        path="/api/security/alerts",
        query_string="limit=25",
        authorization=f"Bearer {TEST_TOKEN}"
    )

    assert captured["status"] == "200 OK"
    assert body["data"]["limit"] == 25
    assert api_integration.last_request["query"]["limit"] == 25


def test_invalid_alert_limit(http_server):

    captured, body = invoke_wsgi(
        http_server.application,
        path="/api/security/alerts",
        query_string="limit=invalid",
        authorization=f"Bearer {TEST_TOKEN}"
    )

    assert captured["status"] == "200 OK"
    assert body["data"]["limit"] is None


def test_unknown_endpoint(http_server):

    captured, body = invoke_wsgi(
        http_server.application,
        path="/api/security/unknown",
        authorization=f"Bearer {TEST_TOKEN}"
    )

    assert captured["status"] == "404 Not Found"
    assert body["error"] == "API endpoint not found"


def test_post_method_rejected(http_server):

    captured, body = invoke_wsgi(
        http_server.application,
        method="POST",
        authorization=f"Bearer {TEST_TOKEN}"
    )

    assert captured["status"] == "405 Method Not Allowed"


def test_security_headers(http_server):

    captured, body = invoke_wsgi(
        http_server.application,
        authorization=f"Bearer {TEST_TOKEN}"
    )

    headers = captured["headers"]

    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert int(headers["Content-Length"]) > 0


def test_json_serialization(http_server):

    captured, body = invoke_wsgi(
        http_server.application,
        authorization=f"Bearer {TEST_TOKEN}"
    )

    assert isinstance(body, dict)


def test_engine_info():

    info = VOINSecurityHTTPServer.engine_info()

    assert info["version"] == "1.0.0"
    assert info["wsgi_support"] is True
    assert info["json_response"] is True
    assert info["status"] == "READY_FOR_TESTING"


def test_create_server_and_close(api_integration):

    server = VOINSecurityHTTPServer(
        api_integration=api_integration,
        port=0
    )

    created_server = server.create_server()

    assert created_server is not None
    assert server.server is created_server

    server.close()

    assert server.server is None


def test_duplicate_server_creation(api_integration):

    server = VOINSecurityHTTPServer(
        api_integration=api_integration,
        port=0
    )

    server.create_server()

    try:

        with pytest.raises(RuntimeError):
            server.create_server()

    finally:
        server.close()


def test_internal_error_is_hidden():

    class FailingIntegration:

        def handle_api_request(self, **kwargs):
            raise RuntimeError("Internal test error")

    server = VOINSecurityHTTPServer(
        api_integration=FailingIntegration()
    )

    captured, body = invoke_wsgi(
        server.application
    )

    assert captured["status"] == "500 Internal Server Error"
    assert body["error"] == "Internal server error"
    assert "Internal test error" not in json.dumps(body)
