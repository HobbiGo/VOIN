"""
VOIN SECURITY MIDDLEWARE TEST SUITE V1.0
"""
import json
import pytest
from security.middleware import VOINSecurityMiddleware
check = lambda condition: (
(_ for _ in ()).throw(
AssertionError("Middleware test failed")
)
if not condition else None
)
make_application = lambda: (
lambda environ, start_response: (
start_response(
"200 OK",
[("Content-Type", "text/plain")]
),
[b"VOIN OK"]
)[1]
)
application = pytest.fixture(
lambda: make_application()
)
middleware = pytest.fixture(
lambda application: VOINSecurityMiddleware(application)
)
invoke = lambda middleware, environ: (
lambda events: (
middleware(
environ,
lambda status, headers, *args: events.update({
"status": status,
"headers": dict(headers)
})
),
events
)
)({})
test_middleware_creation = lambda middleware: (
check(callable(middleware)),
check(middleware.VERSION == "1.0.0")
)[-1]
test_valid_request = lambda middleware: (
lambda result: (
check(result[1]["status"] == "200 OK"),
check(result[0] == [b"VOIN OK"])
)[-1]
)(
invoke(
middleware,
{
"REQUEST_METHOD": "GET",
"PATH_INFO": "/dashboard"
}
)
)
test_request_id_generation = lambda middleware: (
lambda result: (
check("voin.request_id" in result[2]),
check(len(result[2]["voin.request_id"]) == 32),
check(
result[1]["headers"]["X-Request-ID"]
== result[2]["voin.request_id"]
)
)[-1]
)(
(
lambda environ: (
invoke(middleware, environ)[0],
invoke(middleware, environ)[1],
environ
)
)(
{
"REQUEST_METHOD": "GET",
"PATH_INFO": "/dashboard"
}
)
)
test_security_headers = lambda middleware: (
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
middleware,
{
"REQUEST_METHOD": "GET",
"PATH_INFO": "/dashboard"
}
)
)
test_invalid_request = lambda middleware: (
lambda result: (
check(result[1]["status"] == "400 Bad Request"),
check(
json.loads(result[0][0])["error"]
== "Invalid request"
)
)[-1]
)(
invoke(
middleware,
{
"REQUEST_METHOD": "GET",
"PATH_INFO": "invalid-path"
}
)
)
test_missing_request_method = lambda middleware: (
lambda result: (
check(result[1]["status"] == "400 Bad Request"),
check(
json.loads(result[0][0])["error"]
== "Invalid request"
)
)[-1]
)(
invoke(
middleware,
{
"PATH_INFO": "/dashboard"
}
)
)
test_internal_error_handling = lambda monkeypatch: (
lambda engine: (
monkeypatch.setattr(
engine,
"application",
lambda environ, start_response: (
_ for _ in ()
).throw(RuntimeError("test error"))
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
engine,
{
"REQUEST_METHOD": "GET",
"PATH_INFO": "/dashboard"
}
)
)
)-1
test_invalid_application = lambda: (
lambda result: (
check(result is True)
)[-1]
)(
(
lambda: (
pytest.raises(
TypeError,
VOINSecurityMiddleware,
None
)
)()
)()
)
test_engine_info = lambda: (
lambda info: (
check(info["engine"] == "VOIN Security Middleware"),
check(info["version"] == "1.0.0"),
check(info["wsgi_support"] is True),
check(info["request_validation"] is True),
check(info["request_id"] is True),
check(info["security_headers"] is True),
check(info["error_handling"] is True)
)[-1]
)(
VOINSecurityMiddleware.engine_info()
)
