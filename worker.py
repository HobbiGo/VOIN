from js import Response
from security.gateway import VOINSecurityGateway
# Kamu perlu membuat kelas Dummy untuk dashboard agar API bisa jalan
# (Sesuaikan dengan kelas Dashboard asli milikmu jika ada)

class DummyDashboard:
    def get_dashboard(self):
        return {"status": "OPERATIONAL", "message": "VOIN running on Cloudflare"}

# Inisialisasi Gateway (Ganti token dengan token rahasiamu)
API_TOKEN = "voin-secret-token-yang-sangat-panjang-dan-aman-123"
dashboard = DummyDashboard()
gateway = VOINSecurityGateway(
    api_engine=..., # butuh VOINSecurityAPIEngine
    security_integration=..., # butuh VOINSecurityIntegration
    # (Kamu harus import dan inisialisasi engine dengan benar di sini)
)

async def on_fetch(request, env, ctx):
    # 1. Konversi Request Cloudflare ke format WSGI environ
    url = str(request.url)
    method = request.method
    path = request.url.path
    
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": request.url.query or "",
        "HTTP_AUTHORIZATION": request.headers.get("Authorization") or "",
    }
    
    # 2. Siapkan wadah untuk menangkap response WSGI
    response_data = {}
    
    def start_response(status, headers, exc_info=None):
        response_data["status"] = status
        response_data["headers"] = headers

    # 3. Panggil gateway kamu
    body_chunks = gateway.application(environ, start_response)
    body_bytes = b"".join(body_chunks)
    
    # 4. Kembalikan sebagai Response Cloudflare
    return Response.new(
        body_bytes,
        status=int(response_data["status"].split(" ")[0]),
        headers=dict(response_data["headers"])
    )
