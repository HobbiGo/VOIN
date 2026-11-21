import os
from security.api import VOINSecurityAPIEngine # sesuaikan nama modul file API
from security.http_server import VOINSecurityHTTPServer # sesuaikan nama modul HTTP server
# import class dashboard Anda, lalu buat instance-nya, misalnya:
# from security.dashboard import ...

class APIAdapter:
    def __init__(self, api_engine):
        self.api_engine = api_engine

    def handle_api_request(self, method, path, headers=None, query=None):
        return self.api_engine.handle_request(
            method=method,
            path=path,
            headers=headers,
            query=query
        )

api_token = os.environ["API_TOKEN"]
dashboard = ... # isi dengan instance dashboard yang punya method get_dashboard()
api_engine = VOINSecurityAPIEngine(dashboard=dashboard, api_token=api_token)
adapter = APIAdapter(api_engine)

port = int(os.environ.get("PORT", 8080))
server = VOINSecurityHTTPServer(adapter, host="0.0.0.0", port=port)

# Dipakai oleh Gunicorn
application = server.application

if __name__ == "__main__":
    server.serve_forever()
