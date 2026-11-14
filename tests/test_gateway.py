"""
VOIN SECURITY GATEWAY INTEGRATION TESTS V1.1
"""
import pytest
from security.api import VOINSecurityAPIEngine
from security.gateway import VOINSecurityGateway
from security.integration import VOINSecurityIntegration
TEST_TOKEN = "voin-test-api-token-" + ("x" * 40)
make_dashboard = lambda: type(
"FakeDashboard",
(),
{"get_dashboard": lambda self: {"status": "OPERATIONAL"}}
)()
api_engine = pytest.fixture(
lambda: VOINSecurityAPIEngine(
dashboard=make_dashboard(),
api_token=TEST_TOKEN
)
)
security_integration = pytest.fixture(
lambda: VOINSecurityIntegration()
)
gateway = pytest.fixture(
lambda api_engine, security_integration: VOINSecurityGateway(
api_engine=api_engine,
security_integration=security_integration,
host="127.0.0.1",
port=0
)
)
check = lambda condition: (
(_ for _ in ()).throw(AssertionError("Gateway integration test failed"))
if not condition else None
)
test_wallet_authentication_delegation = lambda gateway, monkeypatch: (
monkeypatch.setattr(
gateway.api_integration,
"create_wallet_authentication",
lambda wallet_address: {"success": True, "wallet": wallet_address}
),
check(
gateway.create_wallet_authentication("0x1234")
== {"success": True, "wallet": "0x1234"}
)
)[-1]
test_wallet_verification_delegation = lambda gateway, monkeypatch: (
monkeypatch.setattr(
gateway.api_integration,
"verify_wallet_authentication",
lambda wallet_address, challenge_id, signature: {
"success": True,
"wallet": wallet_address,
"challenge_id": challenge_id
}
),
check(
gateway.verify_wallet_authentication(
wallet_address="0x1234",
challenge_id="challenge-test",
signature="signature-test"
)
== {
"success": True,
"wallet": "0x1234",
"challenge_id": "challenge-test"
}
)
)[-1]
test_api_request_delegation = lambda gateway, monkeypatch: (
monkeypatch.setattr(
gateway.api_integration,
"handle_api_request",
lambda method, path, headers=None, query=None: {
"status_code": 200,
"body": {"success": True}
}
),
check(
gateway.handle_api_request("GET", "/dashboard")
== {
"status_code": 200,
"body": {"success": True}
}
)
)[-1]
test_wsgi_application_delegation = lambda gateway, monkeypatch: (
monkeypatch.setattr(
gateway.http_server,
"application",
lambda environ, start_response: ["gateway-ok"]
),
check(
gateway.application({}, lambda status, headers: None)
== ["gateway-ok"]
)
)[-1]
test_gateway_component_versions = lambda gateway: (
check(gateway.engine_info()["version"] == "1.0.0"),
check(gateway.engine_info()["api_integration"] == gateway.api_integration.VERSION),
check(gateway.engine_info()["http_server"] == gateway.http_server.VERSION)
)[-1]
