"""
VOIN SECURITY GATEWAY ENGINE V1.0

Central gateway connecting:
- VOIN Security Integration
- VOIN Security API
- VOIN Security API Integration
- VOIN Security HTTP Server

Features:
- Unified security gateway
- Wallet authentication delegation
- API request delegation
- HTTP WSGI application
- HTTP server lifecycle management
- Engine validation
- Component status reporting
- Localhost-only default binding
"""

from security.api import VOINSecurityAPIEngine
from security.api_integration import VOINSecurityAPIIntegration
from security.http_server import VOINSecurityHTTPServer
from security.integration import VOINSecurityIntegration


class VOINSecurityGateway:

    VERSION = "1.0.0"

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 8080

    def __init__(
        self,
        api_engine,
        security_integration,
        host=DEFAULT_HOST,
        port=DEFAULT_PORT
    ):

        if not isinstance(
            api_engine,
            VOINSecurityAPIEngine
        ):
            raise TypeError(
                "Invalid VOIN Security API Engine"
            )

        if not isinstance(
            security_integration,
            VOINSecurityIntegration
        ):
            raise TypeError(
                "Invalid VOIN Security Integration Engine"
            )

        self.api_engine = api_engine

        self.security_integration = security_integration

        self.api_integration = VOINSecurityAPIIntegration(
            api_engine=self.api_engine,
            security_integration=self.security_integration
        )

        self.http_server = VOINSecurityHTTPServer(
            api_integration=self.api_integration,
            host=host,
            port=port
        )

    # -----------------------------------------
    # WALLET AUTHENTICATION
    # -----------------------------------------

    def create_wallet_authentication(
        self,
        wallet_address
    ):

        return self.api_integration.create_wallet_authentication(
            wallet_address=wallet_address
        )

    def verify_wallet_authentication(
        self,
        wallet_address,
        challenge_id,
        signature
    ):

        return self.api_integration.verify_wallet_authentication(
            wallet_address=wallet_address,
            challenge_id=challenge_id,
            signature=signature
        )

    # -----------------------------------------
    # API REQUEST
    # -----------------------------------------

    def handle_api_request(
        self,
        method,
        path,
        headers=None,
        query=None
    ):

        return self.api_integration.handle_api_request(
            method=method,
            path=path,
            headers=headers,
            query=query
        )

    # -----------------------------------------
    # HTTP APPLICATION
    # -----------------------------------------

    def application(
        self,
        environ,
        start_response
    ):

        return self.http_server.application(
            environ,
            start_response
        )

    # -----------------------------------------
    # HTTP SERVER MANAGEMENT
    # -----------------------------------------

    def create_server(self):

        return self.http_server.create_server()

    def serve_forever(self):

        return self.http_server.serve_forever()

    def close(self):

        return self.http_server.close()

    # -----------------------------------------
    # ENGINE INFORMATION
    # -----------------------------------------

    def engine_info(self):

        return {
            "engine": "VOIN Security Gateway",
            "version": self.VERSION,

            "security_integration": (
                self.security_integration.VERSION
            ),

            "api_integration": (
                self.api_integration.VERSION
            ),

            "http_server": (
                self.http_server.VERSION
            ),

            "wallet_authentication": True,
            "api_access": True,
            "http_access": True,
            "wsgi_support": True,

            "nonce_protection": True,
            "replay_protection": True,
            "digital_signature": True,
            "persistent_storage": True,
            "security_audit": True,
            "rate_limiting": True,

            "host": self.http_server.host,
            "port": self.http_server.port,

            "status": "READY_FOR_TESTING"
        }
