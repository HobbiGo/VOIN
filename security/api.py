"""
VOIN SECURITY API ENGINE V1.0 (BSC Mainnet / Chain ID 56)

Features:
- Protected security dashboard access
- Security alert access
- Monitoring status access
- Wallet rate-limit status access
- Bearer token authentication
- Constant-time token comparison
- Strict request validation
- Secure error handling
- Read-only API endpoints
"""

import hmac
import re

_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ZERO_ADDRESS = "0x" + ("0" * 40)
DEFAULT_CHAIN_ID = 56


class VOINSecurityAPIEngine:

    VERSION = "1.0.0"

    def __init__(
        self,
        dashboard,
        api_token,
        alert_engine=None,
        monitor_engine=None,
        rate_limit_engine=None
    ):

        if (
            not isinstance(api_token, str)
            or len(api_token) < 32
        ):
            raise ValueError(
                "API token must contain at least 32 characters"
            )

        if dashboard is None:
            raise ValueError(
                "Dashboard engine is required"
            )

        if not callable(
            getattr(dashboard, "get_dashboard", None)
        ):
            raise TypeError(
                "Invalid dashboard engine"
            )

        self.dashboard = dashboard
        self.api_token = api_token

        self.alert_engine = (
            alert_engine
            if alert_engine is not None
            else getattr(dashboard, "alert_engine", None)
        )

        self.monitor_engine = (
            monitor_engine
            if monitor_engine is not None
            else getattr(dashboard, "monitor_engine", None)
        )

        self.rate_limit_engine = (
            rate_limit_engine
            if rate_limit_engine is not None
            else getattr(dashboard, "rate_limit_engine", None)
        )

    @staticmethod
    def _normalize_wallet(wallet_address, *, allow_zero: bool = False) -> str:
        if not isinstance(wallet_address, str):
            raise ValueError("Invalid wallet address")

        cleaned = wallet_address.strip()
        if not cleaned or wallet_address != cleaned:
            raise ValueError("Invalid wallet address")

        if not _EVM_ADDRESS_RE.match(cleaned):
            raise ValueError("Invalid EVM wallet address format")

        normalized = cleaned.lower()
        if not allow_zero and normalized == _ZERO_ADDRESS:
            raise ValueError("Zero address is not allowed")

        return normalized

    @staticmethod
    def _parse_limit(raw_limit):
        if isinstance(raw_limit, bool):
            return None
        if isinstance(raw_limit, int):
            return raw_limit
        if isinstance(raw_limit, str) and raw_limit.isdigit():
            return int(raw_limit)
        return None

    def _response(self, status_code, data):

        return {
            "status_code": status_code,
            "body": data
        }

    def _authenticate(self, headers):

        if not isinstance(headers, dict):
            return False

        authorization = None

        for key, value in headers.items():

            if (
                isinstance(key, str)
                and key.lower() == "authorization"
            ):
                authorization = value
                break

        if not isinstance(authorization, str):
            return False

        scheme, separator, token = authorization.partition(" ")

        if (
            not separator
            or scheme.lower() != "bearer"
            or not token
            or token != token.strip()
            or any(char.isspace() for char in token)
        ):
            return False

        try:

            return hmac.compare_digest(
                token.encode("utf-8"),
                self.api_token.encode("utf-8")
            )

        except (TypeError, ValueError):

            return False

    def get_dashboard(self):

        return self.dashboard.get_dashboard()

    def get_alerts(self, limit=100):

        if self.alert_engine is None:
            return {
                "available": False,
                "alerts": []
            }

        get_alerts = getattr(
            self.alert_engine,
            "get_alerts",
            None
        )

        if not callable(get_alerts):
            return {
                "available": False,
                "alerts": []
            }

        return {
            "available": True,
            "alerts": get_alerts(limit=limit)
        }

    def get_monitoring(self):

        if self.monitor_engine is None:
            return {
                "available": False,
                "status": "NOT_CONFIGURED"
            }

        get_status = getattr(
            self.monitor_engine,
            "get_security_status",
            None
        )

        if not callable(get_status):
            return {
                "available": False,
                "status": "NOT_CONFIGURED"
            }

        return get_status()

    def get_wallet_rate_limit(self, wallet_address):

        normalized_wallet = self._normalize_wallet(wallet_address)

        if self.rate_limit_engine is None:
            return {
                "available": False,
                "status": "NOT_CONFIGURED"
            }

        get_status = getattr(
            self.rate_limit_engine,
            "get_status",
            None
        )

        if not callable(get_status):
            return {
                "available": False,
                "status": "NOT_CONFIGURED"
            }

        return get_status(normalized_wallet)

    def handle_request(
        self,
        method,
        path,
        headers=None,
        query=None
    ):

        if not isinstance(method, str):
            return self._response(
                400,
                {"error": "Invalid HTTP method"}
            )

        if not isinstance(path, str):
            return self._response(
                400,
                {"error": "Invalid API path"}
            )

        if method.upper() != "GET":
            return self._response(
                405,
                {"error": "Method not allowed"}
            )

        if not self._authenticate(headers):
            return self._response(
                401,
                {"error": "Unauthorized"}
            )

        if query is None:
            query = {}

        if not isinstance(query, dict):
            return self._response(
                400,
                {"error": "Invalid query parameters"}
            )

        try:

            if path == "/api/security/dashboard":

                result = self.get_dashboard()

            elif path == "/api/security/alerts":

                limit = self._parse_limit(query.get("limit", 100))

                if limit is None or not 1 <= limit <= 1000:
                    return self._response(
                        400,
                        {"error": "Invalid alert limit"}
                    )

                result = self.get_alerts(limit)

            elif path == "/api/security/monitoring":

                result = self.get_monitoring()

            elif path == "/api/security/rate-limit":

                wallet_address = query.get(
                    "wallet_address"
                )

                try:
                    normalized_wallet = self._normalize_wallet(
                        wallet_address
                    )
                except ValueError:
                    return self._response(
                        400,
                        {"error": "Invalid wallet address"}
                    )

                result = self.get_wallet_rate_limit(
                    normalized_wallet
                )

            else:

                return self._response(
                    404,
                    {"error": "API endpoint not found"}
                )

            return self._response(
                200,
                {
                    "success": True,
                    "chain_id": DEFAULT_CHAIN_ID,
                    "api_version": self.VERSION,
                    "data": result
                }
            )

        except ValueError:

            return self._response(
                400,
                {"error": "Invalid request parameters"}
            )

        except Exception:

            return self._response(
                500,
                {"error": "Internal server error"}
            )

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Security API Engine",
            "version": cls.VERSION,
            "chain_id": DEFAULT_CHAIN_ID,
            "dashboard_api": True,
            "alert_api": True,
            "monitoring_api": True,
            "rate_limit_api": True,
            "bearer_authentication": True,
            "constant_time_comparison": True,
            "strict_validation": True,
            "read_only": True,
            "status": "MAINNET_READY"
        }
