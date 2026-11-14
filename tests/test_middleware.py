"""
VOIN SECURITY MIDDLEWARE TEST SUITE V1.1
"""

import json
import pytest

from security.middleware import VOINSecurityMiddleware


@pytest.fixture
def middleware():
    def application(environ, start_response):
        body = json.dumps({"success": True}).encode("utf-8")
        start_response(
            "200 OK",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body)))
            ]
        )
        return [body]

    return VOINSecurityMiddleware(application)


def invoke(middleware, environ):
    result = {}

    def start_response(status, headers, exc_info=None):
        result["status"] = status
        result["headers"] = dict(headers)

    body = middleware(environ, start_response)

    return {
        "status": result["status"],
        "headers": result["headers"],
        "body": body,
        "json": json.loads(body[0].decode("utf-8"))
    }


def valid_environ():
    return {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/dashboard"
    }


def test_middleware_creation(middleware):
    assert callable(middleware)
    assert middleware.VERSION == "1.0.4"


def test_valid_request(middleware):
    result = invoke(middleware, valid_environ())

    assert result["status"] == "200 OK"
    assert result["json"]["success"] is True


def test_request_id_generation(middleware):
    environ = valid_environ()
    invoke(middleware, environ)

    assert "voin.request_id" in environ
    assert len(environ["voin.request_id"]) == 32


def test_security_headers(middleware):
    result = invoke(middleware, valid_environ())
    headers = result["headers"]

    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Cache-Control"] == "no-store"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert "X-Request-ID" in headers


def test_invalid_request(middleware):
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "invalid-path"
    }

    result = invoke(middleware, environ)

    assert result["status"] == "400 Bad Request"
    assert result["json"]["error"] == "Invalid request"


def test_missing_request_method(middleware):
    environ = {
        "PATH_INFO": "/dashboard"
    }

    result = invoke(middleware, environ)

    assert result["status"] == "400 Bad Request"


def test_internal_error_handling():
    def failing_application(environ, start_response):
        raise RuntimeError("Internal test error")

    engine = VOINSecurityMiddleware(failing_application)
    result = invoke(engine, valid_environ())

    assert result["status"] == "500 Internal Server Error"
    assert result["json"]["error"] == "Internal server error"


def test_invalid_application():
    with pytest.raises(TypeError):
        VOINSecurityMiddleware(None)


def test_engine_info():
    info = VOINSecurityMiddleware.engine_info()

    assert info["engine"] == "VOIN Security Middleware"
    assert info["version"] == "1.0.4"
    assert info["wsgi_support"] is True
    assert info["request_validation"] is True
    assert info["request_id"] is True
    assert info["security_headers"] is True
    assert info["error_handling"] is True
