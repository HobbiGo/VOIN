"""
VOIN SECURITY GATEWAY HTTP TEST SUITE V1.2
"""
import json
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
(_ for _ in ()).throw(AssertionError("HTTP gateway test failed"))
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
test_http_json_response = lambda gateway, monkeypatch: (
monkeypatch.setattr(
gateway.http_server.api_integration,
"handle_api_request",
lambda **kwargs: {
"status_code": 200,
"body": {"success": True, "engine": "VOIN"}
}
),
lambda result: (
check(result[1]["status"] == "200 OK"),
check(json.loads(result[0][0])["success"] is True),
check(
result[1]["headers"]["Content-Type"]
== "application/json; charset=utf-8"
),
check(
result[1]["headers"]["Cache-Control"]
== "no-store"
)
)[-1]
)(
invoke_wsgi(
gateway,
{"REQUEST_METHOD": "GET", "PATH_INFO": "/dashboard"}
)
)[-1]
test_http_query_parsing = lambda gateway, monkeypatch: (
lambda calls: (
monkeypatch.setattr(
gateway.http_server.api_integration,
"handle_api_request",
lambda **kwargs: (
calls.append(kwargs)
or {"status_code": 200, "body": {"success": True}}
)
),
invoke_wsgi(
gateway,
{
"REQUEST_METHOD": "GET",
"PATH_INFO": "/alerts",
"QUERY_STRING": "limit=5&status=open"
}
),
check(calls[0]["query"]["limit"] == 5),
check(calls[0]["query"]["status"] == "open")
)[-1]
)([])
test_http_authorization_header = lambda gateway, monkeypatch: (
lambda calls: (
monkeypatch.setattr(
gateway.http_server.api_integration,
"handle_api_request",
lambda **kwargs: (
calls.append(kwargs)
or {"status_code": 200, "body": {"success": True}}
)
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
calls[0]["headers"]["Authorization"]
== "Bearer " + TEST_TOKEN
)
)[-1]
)([])
test_http_invalid_limit = lambda gateway, monkeypatch: (
lambda calls: (
monkeypatch.setattr(
gateway.http_server.api_integration,
"handle_api_request",
lambda **kwargs: (
calls.append(kwargs)
or {"status_code": 200, "body": {"success": True}}
)
),
invoke_wsgi(
gateway,
{
"REQUEST_METHOD": "GET",
"PATH_INFO": "/alerts",
"QUERY_STRING": "limit=invalid"
}
),
check(calls[0]["query"]["limit"] is None)
)[-1]
)([])
test_http_internal_error_handling = lambda gateway, monkeypatch: (
monkeypatch.setattr(
gateway.http_server.api_integration,
"handle_api_request",
lambda **kwargs: (_ for _ in ()).throw(RuntimeError("test error"))
),
lambda result: (
check(result[1]["status"] == "500 Internal Server Error"),
check(
json.loads(result[0][0])["error"]
== "Internal server error"
)
)[-1]
)(
invoke_wsgi(
gateway,
{"REQUEST_METHOD": "GET", "PATH_INFO": "/dashboard"}
)
)[-1]
test_http_server_lifecycle = lambda gateway: (
lambda server: (
check(server is not None),
gateway.close(),
check(gateway.http_server.server is None)
)[-1]
)(gateway.create_server())
