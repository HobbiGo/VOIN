"""
VOIN SECURITY MIDDLEWARE ENGINE V1.0.5 (BSC Mainnet / Chain ID 56)
"""

import json
import secrets

DEFAULT_CHAIN_ID = 56


def _voin_init(self, application):
    if not callable(application):
        raise TypeError("Invalid WSGI application")

    self.application = application


def _voin_response(self, start_response, status, data, request_id):
    body = json.dumps(data, default=str).encode("utf-8")

    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(body))),
        ("X-Request-ID", request_id)
    ]

    for name, value in self.SECURITY_HEADERS.items():
        headers.append((name, value))

    start_response(status, headers)

    return [body]


def _voin_validate_request(self, environ):
    if not isinstance(environ, dict):
        return False

    method = environ.get("REQUEST_METHOD", "")
    path = environ.get("PATH_INFO", "")

    if not isinstance(method, str) or not method.strip():
        return False

    if not isinstance(path, str) or not path:
        return False

    if not path.startswith("/"):
        return False

    if len(path) > self.MAX_PATH_LENGTH:
        return False

    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        return False

    segments = [seg for seg in path.split("/") if seg]
    if ".." in segments:
        return False

    return True


def _voin_start_response(self, start_response, request_id):

    def wrapped_start_response(status, headers, exc_info=None):

        blocked = (
            "x-request-id",
            "x-content-type-options",
            "x-frame-options",
            "cache-control",
            "referrer-policy"
        )

        updated_headers = [
            (name, value)
            for name, value in headers
            if name.lower() not in blocked
        ]

        updated_headers.append(("X-Request-ID", request_id))

        for name, value in self.SECURITY_HEADERS.items():
            updated_headers.append((name, value))

        # Preserve WSGI start_response calling convention.
        if exc_info is None:
            return start_response(status, updated_headers)

        return start_response(status, updated_headers, exc_info)

    return wrapped_start_response


def _voin_call(self, environ, start_response):
    request_id = secrets.token_hex(16)

    if isinstance(environ, dict):
        environ["voin.request_id"] = request_id

    if not self._validate_request(environ):
        return self._response(
            start_response,
            "400 Bad Request",
            {
                "error": "Invalid request",
                "request_id": request_id
            },
            request_id
        )

    try:
        return self.application(
            environ,
            self._start_response(start_response, request_id)
        )

    except Exception:
        return self._response(
            start_response,
            "500 Internal Server Error",
            {
                "error": "Internal server error",
                "request_id": request_id
            },
            request_id
        )


def _voin_engine_info(cls):
    return {
        "engine": "VOIN Security Middleware",
        "version": cls.VERSION,
        "chain_id": DEFAULT_CHAIN_ID,
        "wsgi_support": True,
        "request_validation": True,
        "request_id": True,
        "security_headers": True,
        "error_handling": True,
        "status": "MAINNET_READY"
    }


VOINSecurityMiddleware = type(
    "VOINSecurityMiddleware",
    (),
    {
        "VERSION": "1.0.5",
        "MAX_PATH_LENGTH": 2048,
        "SECURITY_HEADERS": {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer"
        },
        "__init__": _voin_init,
        "_response": _voin_response,
        "_validate_request": _voin_validate_request,
        "_start_response": _voin_start_response,
        "__call__": _voin_call,
        "engine_info": classmethod(_voin_engine_info)
    }
)
