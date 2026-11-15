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
"""

import pytest

from security.storage import VOINStorageEngine
from security.dashboard import VOINDashboardEngine


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
            "total_events": 10,
            "suspicious_activity": False,
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

    return VOINDashboardEngine(
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

    assert isinstance(dashboard, VOINDashboardEngine)


def test_dashboard_engine_info(dashboard):

    info = dashboard.engine_info()

    assert isinstance(info, dict)

    assert info["engine"] == "VOIN Security Dashboard Engine"

    assert info["version"] == "1.1.0"


def test_event_statistics(dashboard, security_events):

    statistics = dashboard.get_event_statistics()

    assert isinstance(statistics, dict)

    assert "event_breakdown" in statistics

    breakdown = statistics["event_breakdown"]

    assert breakdown["AUTHENTICATION_SUCCESS"] >= 1

    assert breakdown["AUTHENTICATION_FAILED"] >= 1

    assert breakdown["REPLAY_ATTEMPT"] >= 1


def test_alert_statistics(dashboard):

    statistics = dashboard.get_alert_statistics()

    assert statistics["total"] == 2

    assert statistics["by_risk"]["HIGH"] == 1

    assert statistics["by_risk"]["CRITICAL"] == 1


def test_monitoring_status(dashboard):

    status = dashboard.get_monitoring_status()

    assert isinstance(status, dict)

    assert status


def test_engine_status(dashboard):

    status = dashboard.get_engine_status()

    assert isinstance(status, dict)

    assert "storage" in status

    assert "audit" in status

    assert "monitor" in status

    assert "alert" in status

    assert "rate_limit" in status


def test_recent_security_events(dashboard, security_events):

    events = dashboard.get_recent_events(limit=10)

    assert isinstance(events, list)

    assert len(events) == 3

    assert all(isinstance(event, dict) for event in events)


def test_wallet_security_status(dashboard):

    wallet_address = (
        "0x1111111111111111111111111111111111111111"
    )

    status = dashboard.get_wallet_security_status(
        wallet_address
    )

    assert isinstance(status, dict)

    assert status["wallet_address"] == wallet_address

    assert status["blocked"] is False


def test_dashboard_summary(dashboard, security_events):

    result = dashboard.get_dashboard()

    assert isinstance(result, dict)

    assert result["status"] == "READY_FOR_TESTING"

    assert "event_statistics" in result

    assert "alert_statistics" in result

    assert "monitoring" in result

    assert "engine_status" in result

    assert "recent_events" in result


def test_invalid_event_limit(dashboard):

    with pytest.raises(ValueError):

        dashboard.get_recent_events(limit=0)


def test_negative_event_limit(dashboard):

    with pytest.raises(ValueError):

        dashboard.get_recent_events(limit=-1)


def test_invalid_statistics_limit(dashboard):

    with pytest.raises(ValueError):

        dashboard.get_event_statistics(limit=0)


def test_boolean_event_limit_rejected(dashboard):

    with pytest.raises(ValueError):

        dashboard.get_recent_events(limit=True)


def test_boolean_statistics_limit_rejected(dashboard):

    with pytest.raises(ValueError):

        dashboard.get_event_statistics(limit=True)
