"""
VOIN SECURITY GATEWAY TEST SUITE V1.0.3
"""

import pytest

from security.api import VOINSecurityAPIEngine
from security.gateway import VOINSecurityGateway
from security.integration import VOINSecurityIntegration

TEST_TOKEN = "voin-test-api-token-" + ("x" * 40)

make_dashboard = lambda: type("FakeDashboard", (), {"get_dashboard": lambda self: {"status": "OPERATIONAL"}})()

api_engine = pytest.fixture(lambda: VOINSecurityAPIEngine(dashboard=make_dashboard(), api_token=TEST_TOKEN))

security_integration = pytest.fixture(lambda: VOINSecurityIntegration())

gateway = pytest.fixture(lambda api_engine, security_integration: VOINSecurityGateway(api_engine=api_engine, security_integration=security_integration, host="127.0.0.1", port=0))

check = lambda condition: (_ for _ in ()).throw(AssertionError("Test assertion failed")) if not condition else None

test_gateway_creation = lambda gateway: check(isinstance(gateway, VOINSecurityGateway))

test_gateway_version = lambda gateway: check(gateway.VERSION == "1.0.0")

test_gateway_engine_info = lambda gateway: check(isinstance(gateway.engine_info(), dict))

test_gateway_server_creation = lambda gateway: (lambda server: (check(server is not None), gateway.close()))(gateway.create_server())
