"""
VOIN SECURITY MONITORING ENGINE TEST SUITE V1.1.0

Tests:
- Engine initialization
- Engine metadata
- Activity summaries
- Wallet activity
- Authentication monitoring
- Replay monitoring
- Rate limit monitoring
- Invalid challenge monitoring
- Invalid nonce monitoring
- Unauthorized access monitoring
- Multiple simultaneous alerts
- Threshold validation
- Input validation
- Backward compatibility
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


# ============================================================
# ENGINE INITIALIZATION
# ============================================================

def test_monitor_creation(monitor):

    assert isinstance(monitor, VOINSecurityMonitor)


def test_engine_info(monitor):

    info = monitor.engine_info()

    assert info["version"] == "1.1.0"
    assert info["audit_integration"] is True

    assert info["authentication_monitoring"] is True
    assert info["replay_monitoring"] is True

    assert info["rate_limit_monitoring"] is True
    assert info["challenge_monitoring"] is True
    assert info["nonce_monitoring"] is True
    assert info["unauthorized_access_monitoring"] is True

    assert info["threshold_alerts"] is True
    assert info["storage"] == "SQLite"


# ============================================================
# ACTIVITY SUMMARY
# ============================================================

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


def test_unknown_event_classification(monitor):

    class FakeAudit:

        def get_events(self, limit=1000):

            return [
                {"event_type": "UNKNOWN_EVENT"},
                {"event_type": None},
                {},
                {"event_type": 123},
            ]

    test_monitor = VOINSecurityMonitor(
        audit_engine=FakeAudit()
    )

    summary = test_monitor.get_activity_summary()

    assert summary["total_events"] == 4
    assert summary["other_events"] == 4


# ============================================================
# WALLET ACTIVITY
# ============================================================

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


def test_wallet_address_type_validation(monitor):

    with pytest.raises(ValueError):

        monitor.get_wallet_activity(None)


# ============================================================
# AUTHENTICATION FAILURE DETECTION
# ============================================================

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


def test_authentication_failure_below_threshold(monitor):

    for _ in range(4):

        monitor.audit.record_authentication_failure(
            wallet_address=WALLET
        )

    result = monitor.detect_suspicious_activity(
        failure_threshold=5
    )

    assert result["suspicious"] is False


# ============================================================
# REPLAY DETECTION
# ============================================================

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


# ============================================================
# RATE LIMIT DETECTION
# ============================================================

def test_rate_limit_summary(monitor):

    summary = monitor.get_activity_summary()

    assert "rate_limit_exceeded" in summary
    assert summary["rate_limit_exceeded"] == 0


def test_detect_rate_limit_spike(monitor):

    class FakeAudit:

        def get_events(self, limit=100):

            return [
                {"event_type": "RATE_LIMIT_EXCEEDED"}
                for _ in range(5)
            ]

    test_monitor = VOINSecurityMonitor(
        audit_engine=FakeAudit()
    )

    result = test_monitor.detect_suspicious_activity(
        rate_limit_threshold=5
    )

    assert result["suspicious"] is True
    assert result["rate_limit_exceeded"] == 5

    assert any(
        alert["type"] == "RATE_LIMIT_SPIKE"
        for alert in result["alerts"]
    )


# ============================================================
# INVALID CHALLENGE DETECTION
# ============================================================

def test_detect_invalid_challenge_spike():

    class FakeAudit:

        def get_events(self, limit=100):

            return [
                {"event_type": "INVALID_CHALLENGE"}
                for _ in range(5)
            ]

    test_monitor = VOINSecurityMonitor(
        audit_engine=FakeAudit()
    )

    result = test_monitor.detect_suspicious_activity(
        invalid_challenge_threshold=5
    )

    assert result["suspicious"] is True
    assert result["invalid_challenges"] == 5

    assert any(
        alert["type"] == "INVALID_CHALLENGE_SPIKE"
        for alert in result["alerts"]
    )


# ============================================================
# INVALID NONCE DETECTION
# ============================================================

def test_detect_invalid_nonce_spike():

    class FakeAudit:

        def get_events(self, limit=100):

            return [
                {"event_type": "INVALID_NONCE"}
                for _ in range(5)
            ]

    test_monitor = VOINSecurityMonitor(
        audit_engine=FakeAudit()
    )

    result = test_monitor.detect_suspicious_activity(
        invalid_nonce_threshold=5
    )

    assert result["suspicious"] is True
    assert result["invalid_nonces"] == 5

    assert any(
        alert["type"] == "INVALID_NONCE_SPIKE"
        for alert in result["alerts"]
    )


# ============================================================
# UNAUTHORIZED ACCESS DETECTION
# ============================================================

def test_detect_unauthorized_access_spike():

    class FakeAudit:

        def get_events(self, limit=100):

            return [
                {"event_type": "UNAUTHORIZED_ACCESS"}
                for _ in range(3)
            ]

    test_monitor = VOINSecurityMonitor(
        audit_engine=FakeAudit()
    )

    result = test_monitor.detect_suspicious_activity(
        unauthorized_access_threshold=3
    )

    assert result["suspicious"] is True
    assert result["unauthorized_access"] == 3

    assert any(
        alert["type"] == "UNAUTHORIZED_ACCESS_SPIKE"
        for alert in result["alerts"]
    )


# ============================================================
# MULTIPLE ALERTS
# ============================================================

def test_multiple_simultaneous_alerts():

    class FakeAudit:

        def get_events(self, limit=100):

            return (
                [
                    {"event_type": "AUTHENTICATION_FAILED"}
                    for _ in range(5)
                ]
                +
                [
                    {"event_type": "REPLAY_ATTEMPT"}
                    for _ in range(3)
                ]
                +
                [
                    {"event_type": "RATE_LIMIT_EXCEEDED"}
                    for _ in range(5)
                ]
                +
                [
                    {"event_type": "INVALID_CHALLENGE"}
                    for _ in range(5)
                ]
                +
                [
                    {"event_type": "INVALID_NONCE"}
                    for _ in range(5)
                ]
                +
                [
                    {"event_type": "UNAUTHORIZED_ACCESS"}
                    for _ in range(3)
                ]
            )

    test_monitor = VOINSecurityMonitor(
        audit_engine=FakeAudit()
    )

    result = test_monitor.detect_suspicious_activity()

    assert result["suspicious"] is True

    assert len(result["alerts"]) == 6


# ============================================================
# SECURITY STATUS
# ============================================================

def test_security_status_normal(monitor):

    result = monitor.get_security_status()

    assert result["status"] == "NORMAL"
    assert result["version"] == "1.1.0"


def test_security_status_warning(monitor):

    for _ in range(5):

        monitor.audit.record_authentication_failure(
            wallet_address=WALLET
        )

    result = monitor.get_security_status(
        failure_threshold=5
    )

    assert result["status"] == "WARNING"


# ============================================================
# THRESHOLD VALIDATION
# ============================================================

@pytest.mark.parametrize(
    "parameter",
    [
        "window_events",
        "failure_threshold",
        "replay_threshold",
        "rate_limit_threshold",
        "invalid_challenge_threshold",
        "invalid_nonce_threshold",
        "unauthorized_access_threshold",
    ]
)
def test_invalid_threshold_values(monitor, parameter):

    with pytest.raises(ValueError):

        monitor.detect_suspicious_activity(
            **{parameter: 0}
        )


@pytest.mark.parametrize(
    "parameter",
    [
        "window_events",
        "failure_threshold",
        "replay_threshold",
        "rate_limit_threshold",
        "invalid_challenge_threshold",
        "invalid_nonce_threshold",
        "unauthorized_access_threshold",
    ]
)
def test_boolean_threshold_rejected(monitor, parameter):

    with pytest.raises(ValueError):

        monitor.detect_suspicious_activity(
            **{parameter: True}
        )


# ============================================================
# LIMIT VALIDATION
# ============================================================

def test_invalid_limit(monitor):

    with pytest.raises(ValueError):

        monitor.get_activity_summary(limit=0)


def test_boolean_limit_rejected(monitor):

    with pytest.raises(ValueError):

        monitor.get_activity_summary(limit=True)


def test_invalid_detection_window(monitor):

    with pytest.raises(ValueError):

        monitor.detect_suspicious_activity(
            window_events=0
        )


# ============================================================
# BACKWARD COMPATIBILITY
# ============================================================

def test_v10_detection_parameters_remain_supported():

    class FakeAudit:

        def get_events(self, limit=100):

            return []

    test_monitor = VOINSecurityMonitor(
        audit_engine=FakeAudit()
    )

    result = test_monitor.detect_suspicious_activity(
        100,
        5,
        3
    )

    assert result["suspicious"] is False
    assert result["checked_events"] == 0


def test_v10_security_status_parameters_remain_supported():

    class FakeAudit:

        def get_events(self, limit=100):

            return []

    test_monitor = VOINSecurityMonitor(
        audit_engine=FakeAudit()
    )

    result = test_monitor.get_security_status(
        100,
        5,
        3
    )

    assert result["status"] == "NORMAL"
    assert result["version"] == "1.1.0"
