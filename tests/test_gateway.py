"""
VOIN SECURITY GATEWAY TEST SUITE V1.0.2
"""
import pytest
from security.api import VOINSecurityAPIEngine
from security.gateway import VOINSecurityGateway
from security.integration import VOINSecurityIntegration
TEST_TOKEN = "voin-test-api-token-" + ("x" * 40)
def make_dashboard():
return type(
"FakeDashboard",
(),
{
"get_dashboard": lambda self: {
"status": "OPERATIONAL"
}
}
)()
@pytest.fixture
def api_engine():
return VOINSecurityAPIEngine(
dashboard=make_dashboard(),
api_token=TEST_TOKEN
)
@pytest.fixture
def security_integration():
return VOINSecurityIntegration()
@pytest.fixture
def gateway(api_engine, security_integration):
return VOINSecurityGateway(
api_engine=api_engine,
security_integration=security_integration,
host="127.0.0.1",
port=0
)
def test_gateway_creation(gateway):
assert isinstance(gateway, VOINSecurityGateway)
def test_gateway_version(gateway):
assert gateway.VERSION == "1.0.0"
def test_gateway_rejects_invalid_api_engine(security_integration):
with pytest.raises((TypeError, ValueError)):
VOINSecurityGateway(
api_engine=object(),
security_integration=security_integration
)
def test_gateway_rejects_invalid_security_integration(api_engine):
with pytest.raises((TypeError, ValueError)):
VOINSecurityGateway(
api_engine=api_engine,
security_integration=object()
)
def test_gateway_engine_info(gateway):
info = gateway.engine_info()
assert isinstance(info, dict)
assert info

def test_gateway_server_creation(gateway):
server = gateway.create_server()
assert server is not None

gateway.close()

