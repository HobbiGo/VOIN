"""
VOIN SECURITY HTTP SERVER ENGINE V1.0

Features:
- HTTP server adapter for VOIN Security API
- WSGI application interface
- JSON responses
- Query parameter handling
- Bearer token authentication delegation
- Read-only API access
- Localhost-only default binding
- Basic HTTP security headers
"""

import json

from wsgiref.simple_server import make_server
from urllib.parse import parse_qs


class VOINSecurityHTTPServer:

    VERSION = "1.0.0"

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 8080

    def __init__(
        self,
        api_integration,
        host=DEFAULT_HOST,
        port=DEFAULT_PORT
    ):

        if not callable(
            getattr(
                api_integration,
                "handle_api_request",
                None
            )
        ):
            raise TypeError(
                "Invalid VOIN Security API Integration"
            )

        if not isinstance(host, str) or not host:
            raise ValueError("Invalid HTTP host")

        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise ValueError("Invalid HTTP port")

        self.api_integration = api_integration
        self.host = host
        self.port = port
        self.server = None

    def _json_response(self, start_response, status_code, data):

        status_messages = {
            200: "200 OK",
            400: "400 Bad Request",
            401: "401 Unauthorized",
            404: "404 Not Found",
            405: "405 Method Not Allowed",
            500: "500 Internal Server Error"
        }

        status = status_messages.get(
            status_code,
            "500 Internal Server Error"
        )

        body = json.dumps(
            data,
            default=str
        ).encode("utf-8")

        headers = [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff")
        ]

        start_response(status, headers)

        return [body]

    def application(self, environ, start_response):

        try:

            method = environ.get("REQUEST_METHOD", "GET")

            path = environ.get("PATH_INFO", "/")

            headers = {}

            authorization = environ.get(
                "HTTP_AUTHORIZATION"
            )

            if authorization is not None:
                headers["Authorization"] = authorization

            raw_query = environ.get("QUERY_STRING", "")

            parsed_query = parse_qs(
                raw_query,
                keep_blank_values=True
            )

            query = {}

            for key, values in parsed_query.items():

                if values:
                    query[key] = values[0]

            if "limit" in query:

                try:
                    query["limit"] = int(query["limit"])

                except (TypeError, ValueError):
                    query["limit"] = None

            response = self.api_integration.handle_api_request(
                method=method,
                path=path,
                headers=headers,
                query=query
            )

            status_code = response.get(
                "status_code",
                500
            )

            data = response.get(
                "body",
                {"error": "Invalid API response"}
            )

            return self._json_response(
                start_response,
                status_code,
                data
            )

        except Exception:

            return self._json_response(
                start_response,
                500,
                {"error": "Internal server error"}
            )

    def create_server(self):

        if self.server is not None:
            raise RuntimeError(
                "HTTP server has already been created"
            )

        self.server = make_server(
            self.host,
            self.port,
            self.application
        )

        return self.server

    def serve_forever(self):

        server = self.create_server()

        try:
            server.serve_forever()

        finally:
            server.server_close()
            self.server = None

    def close(self):

        if self.server is not None:

            self.server.server_close()
            self.server = None

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Security HTTP Server",
            "version": cls.VERSION,
            "wsgi_support": True,
            "json_response": True,
            "api_integration": True,
            "default_host": cls.DEFAULT_HOST,
            "default_port": cls.DEFAULT_PORT,
            "status": "READY_FOR_TESTING"
        }
