import io
from urllib.parse import urlparse
from js import Response
from security.gateway import VOINSecurityGateway
# Sesuaikan import di bawah ini dengan modul asli di folder security/ Anda:
# from security.api_engine import VOINSecurityAPIEngine
# from security.integration import VOINSecurityIntegration


class DummyDashboard:
    def get_dashboard(self):
        return {"status": "OPERATIONAL", "message": "VOIN running on Cloudflare"}


def build_gateway(env):
    api_token = getattr(env, "API_TOKEN", None) or "voin-secret-token-yang-sangat-panjang-dan-aman-123"
    dashboard = DummyDashboard()

    # TODO: Import dan inisialisasi VOINSecurityAPIEngine & VOINSecurityIntegration asli di sini
    api_engine = None
    security_integration = None

    return VOINSecurityGateway(
        api_engine=api_engine,
        security_integration=security_integration,
        dashboard=dashboard,
        api_token=api_token,
    )


async def _read_request_body_bytes(request) -> bytes:
    method = (request.method or "GET").upper()
    if method in ("GET", "HEAD"):
        return b""
    text_body = await request.text()
    if not text_body:
        return b""
    return text_body.encode("utf-8")


async def on_fetch(request, env, ctx):
    gateway = build_gateway(env)

    parsed = urlparse(str(request.url))
    method = (request.method or "GET").upper()
    path = parsed.path or "/"
    query_string = parsed.query or ""

    auth_header = request.headers.get("Authorization") or ""
    content_type = request.headers.get("Content-Type") or ""
    body_bytes_in = await _read_request_body_bytes(request)

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query_string,
        "HTTP_AUTHORIZATION": auth_header,
        "CONTENT_TYPE": content_type,
        "CONTENT_LENGTH": str(len(body_bytes_in)),
        "wsgi.input": io.BytesIO(body_bytes_in),
        "wsgi.url_scheme": parsed.scheme or "https",
        "SERVER_NAME": parsed.hostname or "localhost",
        "SERVER_PORT": str(parsed.port or (443 if (parsed.scheme or "https") == "https" else 80)),
    }

    response_data = {
        "status": "500 Internal Server Error",
        "headers": [],
    }

    def start_response(status, headers, exc_info=None):
        response_data["status"] = status
        response_data["headers"] = headers

    body_chunks = gateway.application(environ, start_response)
    body_bytes_out = b"".join(body_chunks)
    status_code = int(str(response_data["status"]).split(" ")[0])

    return Response.new(
        body_bytes_out,
        status=status_code,
        headers=dict(response_data["headers"]),
    )
