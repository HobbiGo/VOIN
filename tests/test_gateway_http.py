"""
VOIN SECURITY GATEWAY HTTP TEST SUITE V1.2.2
"""

import json
from unittest.mock import Mock

import pytest

from security.api import VOINSecurityAPIEngine
from security.gateway import VOINSecurityGateway
from security.integration import VOINSecurityIntegration


TEST_TOKEN = "voin-test-api-token-" + ("x" * 40)


make_dashboard = lambda: type(
    "FakeDashboard",
    (),
    {"get_dashboard": lambda self: {"status": "OPERATIONAL"}}
)()


api_engine = pytest.fixture(
    lambda: VOINSecurityAPIEngine(
        dashboard=make_dashboard(),
        api_token=TEST_TOKEN
    )
)


security_integration = pytest.fixture(
    lambda: VOINSecurityIntegration()
)


gateway = pytest.fixture(
    lambda api_engine, security_integration: VOINSecurityGateway(
        api_engine=api_engine,
        security_integration=security_integration,
        host="127.0.0.1",
        port=0
    )
)


check = lambda condition: (
    (_ for _ in ()).throw(
        AssertionError("Gateway HTTP test failed")
    )
    if not condition else None
)


invoke_wsgi = lambda gateway, environ: (
    lambda events: (
        gateway.application(
            environ,
            lambda status, headers: events.update({
                "status": status,
                "headers": dict(headers)
            })
        ),
        events
    )
)({})


check_response = lambda result, expected_status, expected_body: (
    check(result[1]["status"] == expected_status),
    check(json.loads(result[0][0]) == expected_body),
    check(
        result[1]["headers"]["Content-Type"]
        == "application/json; charset=utf-8"
    ),
    check(result[1]["headers"]["Cache-Control"] == "no-store"),
    check(
        result[1]["headers"]["X-Content-Type-Options"]
        == "nosniff"
    )
)[-1]


test_http_json_response = lambda gateway, monkeypatch: (
    monkeypatch.setattr(
        gateway.http_server.api_integration,
        "handle_api_request",
        lambda **kwargs: {
            "status_code": 200,
            "body": {
                "success": True,
                "engine": "VOIN"
            }
        }
    ),
    check_response(
        invoke_wsgi(
            gateway,
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/dashboard"
            }
        ),
        "200 OK",
        {
            "success": True,
            "engine": "VOIN"
        }
    )
)[-1]


test_http_query_parsing = lambda gateway, monkeypatch: (
    lambda spy: (
        monkeypatch.setattr(
            gateway.http_server.api_integration,
            "handle_api_request",
            spy
        ),
        invoke_wsgi(
            gateway,
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/alerts",
                "QUERY_STRING": "limit=5&status=open"
            }
        ),
        check(spy.call_args.kwargs["query"]["limit"] == 5),
        check(spy.call_args.kwargs["query"]["status"] == "open")
    )[-1]
)(
    Mock(
        return_value={
            "status_code": 200,
            "body": {"success": True}
        }
    )
)


test_http_authorization_header = lambda gateway, monkeypatch: (
    lambda spy: (
        monkeypatch.setattr(
            gateway.http_server.api_integration,
            "handle_api_request",
            spy
        ),
        invoke_wsgi(
            gateway,
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/dashboard",
                "HTTP_AUTHORIZATION": "Bearer " + TEST_TOKEN
            }
        ),
        check(
            spy.call_args.kwargs["headers"]["Authorization"]
            == "Bearer " + TEST_TOKEN
        )
    )[-1]
)(
    Mock(
        return_value={
            "status_code": 200,
            "body": {"success": True}
        }
    )
)


test_http_invalid_limit = lambda gateway, monkeypatch: (
    lambda spy: (
        monkeypatch.setattr(
            gateway.http_server.api_integration,
            "handle_api_request",
            spy
        ),
        invoke_wsgi(
            gateway,
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/alerts",
                "QUERY_STRING": "limit=invalid"
            }
        ),
        check(spy.call_args.kwargs["query"]["limit"] is None)
    )[-1]
)(
    Mock(
        return_value={
            "status_code": 200,
            "body": {"success": True}
        }
    )
)


test_http_internal_error_handling = lambda gateway, monkeypatch: (
    monkeypatch.setattr(
        gateway.http_server.api_integration,
        "handle_api_request",
        lambda **kwargs: (_ for _ in ()).throw(
            RuntimeError("test error")
        )
    ),
    check_response(
        invoke_wsgi(
            gateway,
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/dashboard"
            }
        ),
        "500 Internal Server Error",
        {
            "error": "Internal server error"
        }
    )
)[-1]


test_http_server_lifecycle = lambda gateway: (
    lambda server: (
        check(server is not None),
        gateway.close(),
        check(gateway.http_server.server is None)
    )[-1]
)(
    gateway.create_server()
)
