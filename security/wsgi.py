import os
import threading

from security.api import VOINSecurityAPIEngine
from security.http_server import VOINSecurityHTTPServer

_INIT_LOCK = threading.Lock()
_CACHED_SERVER = None
_CACHED_APP = None


class FallbackDashboard:
    def get_dashboard(self):
        return {
            "status": "OPERATIONAL",
            "engine": "VOIN Security Dashboard",
            "source": "security.wsgi",
        }


class APIAdapter:
    def __init__(self, api_engine):
        self.api_engine = api_engine

    def handle_api_request(self, method, path, headers=None, query=None):
        return self.api_engine.handle_request(
            method=method,
            path=path,
            headers=headers,
            query=query,
        )


def _get_api_token():
    token = os.environ.get("API_TOKEN", "").strip()
    if len(token) < 32:
        raise ValueError("API_TOKEN environment variable must be at least 32 characters")
    return token


def _get_port():
    raw_port = os.environ.get("PORT", "8080").strip()
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise ValueError("PORT environment variable must be a valid integer") from exc

    if not (1 <= port <= 65535):
        raise ValueError("PORT environment variable must be between 1 and 65535")

    return port


def create_application():
    api_token = _get_api_token()
    port = _get_port()
    host = os.environ.get("HOST", "0.0.0.0").strip() or "0.0.0.0"

    dashboard = FallbackDashboard()
    api_engine = VOINSecurityAPIEngine(
        dashboard=dashboard,
        api_token=api_token,
    )
    adapter = APIAdapter(api_engine)
    http_server = VOINSecurityHTTPServer(
        adapter,
        host=host,
        port=port,
    )
    return http_server, http_server.application


def get_server_and_application():
    global _CACHED_SERVER, _CACHED_APP

    if _CACHED_SERVER is not None and _CACHED_APP is not None:
        return _CACHED_SERVER, _CACHED_APP

    with _INIT_LOCK:
        if _CACHED_SERVER is None or _CACHED_APP is None:
            _CACHED_SERVER, _CACHED_APP = create_application()

    return _CACHED_SERVER, _CACHED_APP


def application(environ, start_response):
    _, wsgi_app = get_server_and_application()
    return wsgi_app(environ, start_response)


if __name__ == "__main__":
    server, _ = get_server_and_application()
    server.serve_forever()
