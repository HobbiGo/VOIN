"""
VOIN SECURITY GATEWAY MIDDLEWARE TEST SUITE V1.0
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
(_ for _ in ()).throw(
AssertionError("Gateway Middleware test failed")
)
if not condition else None
)
invoke = lambda gateway, environ: (
lambda events: (
gateway.application(
environ,
lambda status, headers, *args: events.update({
"status": status,
"headers": dict(headers)
})
),
events,
environ
)
)({})
test_gateway_middleware_enabled = lambda gateway: (
check(gateway.middleware is not None),
check(gateway.middleware.VERSION == "1.0.0"),
check(gateway.engine_info()["middleware_enabled"] is True)
)[-1]
test_gateway_middleware_valid_request = lambda gateway, monkeypatch: (
monkeypatch.setattr(
gateway.http_server.api_integration,
"handle_api_request",
lambda **kwargs: {
"status_code": 200,
"body": {"success": True}
}
),
lambda result: (
check(result[1]["status"] == "200 OK"),
check(json.loads(result[0][0]) == {"success": True})
)[-1]
)(
invoke(
gateway,
{
"REQUEST_METHOD": "GET",
"PATH_INFO": "/dashboard"
}
)
)[-1]
test_gateway_middleware_request_id = lambda gateway, monkeypatch: (
monkeypatch.setattr(
gateway.http_server.api_integration,
"handle_api_request",
lambda **kwargs: {
"status_code": 200,
"body": {"success": True}
}
),
lambda result: (
check("voin.request_id" in result[2]),
check(len(result[2]["voin.request_id"]) == 32),
check(
result[1]["headers"]["X-Request-ID"]
== result[2]["voin.request_id"]
)
)[-1]
)(
invoke(
gateway,
{
"REQUEST_METHOD": "GET",
"PATH_INFO": "/dashboard"
}
)
)[-1]
test_gateway_middleware_security_headers = lambda gateway, monkeypatch: (
monkeypatch.setattr(
gateway.http_server.api_integration,
"handle_api_request",
lambda **kwargs: {
"status_code": 200,
"body": {"success": True}
}
),
lambda result: (
check(
result[1]["headers"]["X-Content-Type-Options"]
== "nosniff"
),
check(
result[1]["headers"]["X-Frame-Options"]
== "DENY"
),
check(
result[1]["headers"]["Cache-Control"]
== "no-store"
),
check(
result[1]["headers"]["Referrer-Policy"]
== "no-referrer"
)
)[-1]
)(
invoke(
gateway,
{
"REQUEST_METHOD": "GET",
"PATH_INFO": "/dashboard"
}
)
)[-1]
test_gateway_middleware_rejects_invalid_path = lambda gateway: (
lambda result: (
check(result[1]["status"] == "400 Bad Request"),
check(
json.loads(result[0][0])["error"]
== "Invalid request"
)
)[-1]
)(
invoke(
gateway,
{
"REQUEST_METHOD": "GET",
"PATH_INFO": "invalid-path"
}
)
)
test_gateway_middleware_handles_internal_error = lambda gateway, monkeypatch: (
monkeypatch.setattr(
gateway.http_server.api_integration,
"handle_api_request",
lambda **kwargs: (_ for _ in ()).throw(
RuntimeError("test error")
)
),
lambda result: (
check(
result[1]["status"]
== "500 Internal Server Error"
),
check(
json.loads(result[0][0])["error"]
== "Internal server error"
)
)[-1]
)(
invoke(
gateway,
{
"REQUEST_METHOD": "GET",
"PATH_INFO": "/dashboard"
}
)
)[-1]
