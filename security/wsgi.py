import os
from security.api import VOINSecurityAPIEngine
from security.http_server import VOINSecurityHTTPServer


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


def create_application():
    api_token = _get_api_token()
    dashboard = FallbackDashboard()
    api_engine = VOINSecurityAPIEngine(
        dashboard=dashboard,
        api_token=api_token,
    )
    adapter = APIAdapter(api_engine)
    port = int(os.environ.get("PORT", 8080))
    http_server = VOINSecurityHTTPServer(
        adapter,
        host="0.0.0.0",
        port=port,
    )
    return http_server, http_server.application


_server, application = create_application()

if __name__ == "__main__":
    _server.serve_forever()
