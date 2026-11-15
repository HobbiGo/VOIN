"""
VOIN SECURITY DASHBOARD ENGINE TEST SUITE V1.0

Tests:
- Dashboard engine creation
- Engine information
- Event statistics
- Alert statistics
- Monitoring status
- Engine status
- Recent security events
- Wallet security status
- Dashboard summary
- Input validation
- Optional component handling
"""

import pytest

from security.storage import VOINStorageEngine
from security.dashboard import VOINSecurityDashboard


class FakeAlertEngine:

    def get_alert_summary(self):
        return {
            "total": 2,
            "by_risk": {
                "LOW": 0,
                "MEDIUM": 0,
                "HIGH": 1,
                "CRITICAL": 1,
            },
            "by_status": {
                "OPEN": 2,
                "ACKNOWLEDGED": 0,
                "RESOLVED": 0,
            },
        }

    def engine_info(self):
        return {
            "engine": "VOIN Security Alert Engine",
            "version": "1.0.0",
            "status": "READY_FOR_TESTING",
        }


class FakeMonitorEngine:

    def get_security_status(self):
        return {
            "status": "ACTIVE",
            "monitoring": {
                "enabled": True,
            },
            "version": "1.1.0",
        }

    def engine_info(self):
        return {
            "engine": "VOIN Security Monitor Engine",
            "version": "1.1.0",
            "status": "READY_FOR_TESTING",
        }


class FakeRateLimitEngine:

    def get_status(self, wallet_address):
        return {
            "wallet_address": wallet_address,
            "blocked": False,
            "attempts": 1,
        }

    def engine_info(self):
        return {
            "engine": "VOIN Rate Limit Engine",
            "version": "1.0.0",
            "status": "READY_FOR_TESTING",
        }


class FakeAuditEngine:

    def engine_info(self):
        return {
            "engine": "VOIN Audit Engine",
            "version": "1.1.0",
            "status": "READY_FOR_TESTING",
        }


@pytest.fixture
def storage(tmp_path):

    database = tmp_path / "voin_dashboard_test.db"

    return VOINStorageEngine(str(database))


@pytest.fixture
def dashboard(storage):

    return VOINSecurityDashboard(
        storage=storage,
        audit_engine=FakeAuditEngine(),
        monitor_engine=FakeMonitorEngine(),
        alert_engine=FakeAlertEngine(),
        rate_limit_engine=FakeRateLimitEngine(),
    )


@pytest.fixture
def security_events(storage):

    storage.log_event(
        "AUTHENTICATION_SUCCESS",
        "0x1111111111111111111111111111111111111111",
        "challenge-001",
    )

    storage.log_event(
        "AUTHENTICATION_FAILED",
        "0x2222222222222222222222222222222222222222",
        "challenge-002",
    )

    storage.log_event(
        "REPLAY_ATTEMPT",
        "0x3333333333333333333333333333333333333333",
        "challenge-003",
    )

    return storage.get_security_events()


def test_dashboard_engine_creation(dashboard):

    assert isinstance(
        dashboard,
        VOINSecurityDashboard
    )


def test_dashboard_engine_info(dashboard):

    info = dashboard.engine_info()

    assert info["engine"] == "VOIN Security Dashboard"

    assert info["version"] == "1.1.0"

    assert info["security_statistics"] is True

    assert info["alert_monitoring"] is True

    assert info["security_monitoring"] is True

    assert info["status"] == "READY_FOR_TESTING"


def test_event_statistics(dashboard, security_events):

    statistics = dashboard.get_event_statistics()

    assert statistics["total_events"] == 3

    assert statistics["authentication_success"] == 1

    assert statistics["authentication_failed"] == 1

    assert statistics["replay_attempts"] == 1

    breakdown = statistics["event_breakdown"]

    assert breakdown["AUTHENTICATION_SUCCESS"] == 1

    assert breakdown["AUTHENTICATION_FAILED"] == 1

    assert breakdown["REPLAY_ATTEMPT"] == 1


def test_alert_statistics(dashboard):

    statistics = dashboard.get_alert_statistics()

    assert statistics["available"] is True

    assert statistics["alerts"]["total"] == 2

    assert statistics["alerts"]["by_risk"]["HIGH"] == 1

    assert statistics["alerts"]["by_risk"]["CRITICAL"] == 1


def test_monitoring_status(dashboard):

    status = dashboard.get_monitoring_status()

    assert status["available"] is True

    assert status["status"] == "ACTIVE"

    assert status["monitoring"]["enabled"] is True

    assert status["version"] == "1.1.0"


def test_engine_status(dashboard):

    status = dashboard.get_engine_status()

    assert "storage" in status

    assert "audit" in status

    assert "monitor" in status

    assert "alert" in status

    assert "rate_limiting" in status

    assert status["audit"]["available"] is True

    assert status["monitor"]["available"] is True

    assert status["alert"]["available"] is True

    assert status["rate_limiting"]["available"] is True


def test_recent_security_events(dashboard, security_events):

    result = dashboard.get_recent_events(limit=10)

    assert isinstance(result, dict)

    assert result["total"] == 3

    assert isinstance(result["events"], list)

    assert len(result["events"]) == 3

    assert all(
        isinstance(event, dict)
        for event in result["events"]
    )


def test_wallet_security_status(dashboard):

    wallet_address = (
        "0x1111111111111111111111111111111111111111"
    )

    result = dashboard.get_wallet_security_status(
        wallet_address
    )

    assert result["available"] is True

    assert result["rate_limit"]["wallet_address"] == wallet_address

    assert result["rate_limit"]["blocked"] is False


def test_dashboard_summary(dashboard, security_events):

    result = dashboard.get_dashboard()

    assert result["dashboard"] == "VOIN Security Dashboard"

    assert result["version"] == "1.1.0"

    assert result["status"] == "READY_FOR_TESTING"

    assert "generated_at" in result

    assert "security_statistics" in result

    assert "alert_statistics" in result

    assert "monitoring_status" in result

    assert "engine_status" in result

    assert "recent_events" in result

    assert result["security_statistics"]["total_events"] == 3


def test_alert_engine_not_configured(storage):

    dashboard = VOINSecurityDashboard(
        storage=storage
    )

    result = dashboard.get_alert_statistics()

    assert result["available"] is False

    assert result["alerts"] == {}


def test_monitor_engine_not_configured(storage):

    dashboard = VOINSecurityDashboard(
        storage=storage
    )

    result = dashboard.get_monitoring_status()

    assert result["available"] is False

    assert result["status"] == "NOT_CONFIGURED"


def test_rate_limit_engine_not_configured(storage):

    dashboard = VOINSecurityDashboard(
        storage=storage
    )

    result = dashboard.get_wallet_security_status(
        "0x1111111111111111111111111111111111111111"
    )

    assert result["available"] is False

    assert result["status"] == "RATE_LIMITING_NOT_CONFIGURED"


def test_invalid_event_limit(dashboard):

    with pytest.raises(ValueError):

        dashboard.get_recent_events(limit=0)


def test_negative_event_limit(dashboard):

    with pytest.raises(ValueError):

        dashboard.get_recent_events(limit=-1)


def test_boolean_event_limit_rejected(dashboard):

    with pytest.raises(ValueError):

        dashboard.get_recent_events(limit=True)


def test_invalid_statistics_limit(dashboard):

    with pytest.raises(ValueError):

        dashboard.get_event_statistics(limit=0)


def test_boolean_statistics_limit_rejected(dashboard):

    with pytest.raises(ValueError):

        dashboard.get_event_statistics(limit=True)


def test_string_event_limit_rejected(dashboard):

    with pytest.raises(ValueError):

        dashboard.get_recent_events(limit="10")


def test_string_statistics_limit_rejected(dashboard):

    with pytest.raises(ValueError):

        dashboard.get_event_statistics(limit="100")
