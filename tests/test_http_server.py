"""
VOIN SECURITY HTTP SERVER TEST SUITE V1.0
"""

import json
import pytest

from security.http_server import VOINSecurityHTTPServer


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

        return {
            "status_code": 200,
            "body": {
                "success": True,
                "method": method,
                "path": path,
                "query": query
            }
        }


@pytest.fixture
def api_integration():
    return FakeAPIIntegration()


@pytest.fixture
def http_server(api_integration):
    return VOINSecurityHTTPServer(api_integration)


def call_application(server, environ):

    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = headers

    response = server.application(
        environ,
        start_response
    )

    body = b"".join(response)

    return captured, body


def test_server_creation(api_integration):

    server = VOINSecurityHTTPServer(api_integration)

    assert server.host == "127.0.0.1"
    assert server.port == 8080
    assert server.server is None


def test_invalid_host(api_integration):

    with pytest.raises(ValueError):
        VOINSecurityHTTPServer(
            api_integration,
            host=""
        )


@pytest.mark.parametrize(
    "port",
    [-1, 65536, True, "8080"]
)
def test_invalid_port(api_integration, port):

    with pytest.raises(ValueError):
        VOINSecurityHTTPServer(
            api_integration,
            port=port
        )


def test_port_zero_is_allowed(api_integration):

    server = VOINSecurityHTTPServer(
        api_integration,
        port=0
    )

    assert server.port == 0


def test_wsgi_application(http_server):

    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/api/security/dashboard",
        "QUERY_STRING": ""
    }

    captured, body = call_application(
        http_server,
        environ
    )

    assert captured["status"] == "200 OK"
    assert json.loads(body)["success"] is True


def test_authorization_header_delegation(
    http_server,
    api_integration
):

    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/api/security/dashboard",
        "QUERY_STRING": "",
        "HTTP_AUTHORIZATION": "Bearer test-token"
    }

    call_application(http_server, environ)

    assert (
        api_integration.last_request["headers"]["Authorization"]
        == "Bearer test-token"
    )


def test_query_parameter_handling(
    http_server,
    api_integration
):

    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/api/security/alerts",
        "QUERY_STRING": "limit=10"
    }

    call_application(http_server, environ)

    assert api_integration.last_request["query"]["limit"] == 10


def test_invalid_query_limit(
    http_server,
    api_integration
):

    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/api/security/alerts",
        "QUERY_STRING": "limit=invalid"
    }

    call_application(http_server, environ)

    assert api_integration.last_request["query"]["limit"] is None


def test_unknown_route(http_server):

    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/unknown",
        "QUERY_STRING": ""
    }

    captured, _ = call_application(http_server, environ)

    assert captured["status"] == "200 OK"


def test_post_request(http_server):

    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/api/security/dashboard",
        "QUERY_STRING": ""
    }

    captured, _ = call_application(http_server, environ)

    assert captured["status"] == "200 OK"


def test_security_headers(http_server):

    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/api/security/dashboard",
        "QUERY_STRING": ""
    }

    captured, _ = call_application(http_server, environ)

    headers = dict(captured["headers"])

    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Content-Type"] == "application/json; charset=utf-8"


def test_json_response(http_server):

    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/api/security/dashboard",
        "QUERY_STRING": ""
    }

    _, body = call_application(http_server, environ)

    assert isinstance(json.loads(body), dict)


def test_engine_info():

    info = VOINSecurityHTTPServer.engine_info()

    assert info["engine"] == "VOIN Security HTTP Server"
    assert info["version"] == "1.0.0"
    assert info["wsgi_support"] is True


def test_create_server_and_close(api_integration):

    server = VOINSecurityHTTPServer(
        api_integration,
        port=0
    )

    created_server = server.create_server()

    assert created_server is not None
    assert server.server is created_server

    server.close()

    assert server.server is None


def test_duplicate_server_creation(api_integration):

    server = VOINSecurityHTTPServer(
        api_integration,
        port=0
    )

    server.create_server()

    try:
        with pytest.raises(RuntimeError):
            server.create_server()
    finally:
        server.close()


def test_internal_server_error():

    class BrokenIntegration:

        def handle_api_request(self, **kwargs):
            raise RuntimeError("Internal failure")

    server = VOINSecurityHTTPServer(BrokenIntegration())

    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/api/security/dashboard",
        "QUERY_STRING": ""
    }

    captured, body = call_application(server, environ)

    assert captured["status"] == "500 Internal Server Error"
    assert json.loads(body)["error"] == "Internal server error"
