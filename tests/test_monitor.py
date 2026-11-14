"""
VOIN SECURITY MONITORING ENGINE TEST SUITE V1.0

Tests activity summaries, suspicious activity detection,
security status and input validation.
"""

import pytest

from security.storage import VOINStorageEngine
from security.audit import VOINAuditEngine
from security.monitor import VOINSecurityMonitor


WALLET = "0x1234567890123456789012345678901234567890"


@pytest.fixture
def monitor(tmp_path):

    db_path = tmp_path / "monitor_test.db"

    storage = VOINStorageEngine(str(db_path))
    audit = VOINAuditEngine(storage=storage)

    return VOINSecurityMonitor(audit_engine=audit)


def test_monitor_creation(monitor):

    assert isinstance(monitor, VOINSecurityMonitor)


def test_engine_info(monitor):

    info = monitor.engine_info()

    assert info["version"] == "1.0.0"
    assert info["audit_integration"] is True
    assert info["authentication_monitoring"] is True
    assert info["replay_monitoring"] is True


def test_empty_activity_summary(monitor):

    summary = monitor.get_activity_summary()

    assert summary["total_events"] == 0
    assert summary["authentication_success"] == 0
    assert summary["authentication_failed"] == 0
    assert summary["replay_attempts"] == 0


def test_authentication_success_summary(monitor):

    monitor.audit.record_authentication_success(
        wallet_address=WALLET,
        challenge_id="challenge-001"
    )

    summary = monitor.get_activity_summary()

    assert summary["authentication_success"] == 1
    assert summary["total_events"] == 1


def test_authentication_failure_summary(monitor):

    for _ in range(3):

        monitor.audit.record_authentication_failure(
            wallet_address=WALLET
        )

    summary = monitor.get_activity_summary()

    assert summary["authentication_failed"] == 3


def test_replay_attempt_summary(monitor):

    for _ in range(2):

        monitor.audit.record_replay_attempt(
            wallet_address=WALLET
        )

    summary = monitor.get_activity_summary()

    assert summary["replay_attempts"] == 2


def test_detect_authentication_failure_spike(monitor):

    for _ in range(5):

        monitor.audit.record_authentication_failure(
            wallet_address=WALLET
        )

    result = monitor.detect_suspicious_activity(
        failure_threshold=5
    )

    assert result["suspicious"] is True
    assert result["authentication_failures"] == 5

    assert any(
        alert["type"] == "AUTHENTICATION_FAILURE_SPIKE"
        for alert in result["alerts"]
    )


def test_detect_replay_activity_spike(monitor):

    for _ in range(3):

        monitor.audit.record_replay_attempt(
            wallet_address=WALLET
        )

    result = monitor.detect_suspicious_activity(
        replay_threshold=3
    )

    assert result["suspicious"] is True
    assert result["replay_attempts"] == 3

    assert any(
        alert["type"] == "REPLAY_ACTIVITY_SPIKE"
        for alert in result["alerts"]
    )


def test_no_suspicious_activity_below_threshold(monitor):

    monitor.audit.record_authentication_failure(
        wallet_address=WALLET
    )

    result = monitor.detect_suspicious_activity(
        failure_threshold=5,
        replay_threshold=3
    )

    assert result["suspicious"] is False
    assert result["alerts"] == []


def test_security_status_normal(monitor):

    result = monitor.get_security_status()

    assert result["status"] == "NORMAL"


def test_security_status_warning(monitor):

    for _ in range(5):

        monitor.audit.record_authentication_failure(
            wallet_address=WALLET
        )

    result = monitor.get_security_status(
        failure_threshold=5
    )

    assert result["status"] == "WARNING"


def test_get_wallet_activity(monitor):

    monitor.audit.record_authentication_success(
        wallet_address=WALLET,
        challenge_id="challenge-002"
    )

    events = monitor.get_wallet_activity(WALLET)

    assert len(events) == 1


def test_invalid_wallet_address(monitor):

    with pytest.raises(ValueError):

        monitor.get_wallet_activity("")


def test_invalid_limit(monitor):

    with pytest.raises(ValueError):

        monitor.get_activity_summary(limit=0)


def test_invalid_threshold(monitor):

    with pytest.raises(ValueError):

        monitor.detect_suspicious_activity(
            failure_threshold=0
        )


def test_boolean_limit_rejected(monitor):

    with pytest.raises(ValueError):

        monitor.get_activity_summary(limit=True)
