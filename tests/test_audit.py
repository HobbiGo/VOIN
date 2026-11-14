"""
VOIN SECURITY AUDIT ENGINE TESTS V1.0
"""

import pytest

from security.audit import VOINAuditEngine
from security.storage import VOINStorageEngine


@pytest.fixture
def audit(tmp_path):
    storage = VOINStorageEngine(
        str(tmp_path / "audit_test.db")
    )
    return VOINAuditEngine(storage=storage)


WALLET = "0x1234567890abcdef1234567890abcdef12345678"


def test_engine_info(audit):
    info = audit.engine_info()

    assert info["version"] == "1.0.0"
    assert info["event_recording"] is True
    assert info["wallet_audit_history"] is True


def test_record_authentication_success(audit):
    result = audit.record_authentication_success(
        WALLET,
        "challenge_001"
    )

    assert result is True

    events = audit.get_events()

    assert events[0]["event_type"] == "AUTHENTICATION_SUCCESS"


def test_record_authentication_failure(audit):
    audit.record_authentication_failure(
        WALLET,
        "challenge_002",
        "INVALID_SIGNATURE"
    )

    events = audit.get_events()

    assert events[0]["event_type"] == "AUTHENTICATION_FAILED"


def test_record_replay_attempt(audit):
    audit.record_replay_attempt(
        WALLET,
        "challenge_003"
    )

    events = audit.get_events()

    assert events[0]["event_type"] == "REPLAY_ATTEMPT"


def test_record_security_warning(audit):
    audit.record_security_warning(
        WALLET,
        reason="SUSPICIOUS_ACTIVITY"
    )

    events = audit.get_events()

    assert events[0]["event_type"] == "SECURITY_WARNING"


def test_wallet_audit_history(audit):
    audit.record_authentication_success(
        WALLET,
        "challenge_004"
    )

    audit.record_authentication_failure(
        "0xabcdef1234567890abcdef1234567890abcdef12",
        "challenge_005"
    )

    events = audit.get_wallet_events(WALLET)

    assert len(events) == 1
    assert events[0]["event_type"] == "AUTHENTICATION_SUCCESS"


def test_generate_report(audit):
    audit.record_authentication_success(
        WALLET,
        "challenge_006"
    )

    audit.record_authentication_failure(
        WALLET,
        "challenge_007"
    )

    audit.record_replay_attempt(
        WALLET,
        "challenge_008"
    )

    audit.record_security_warning(
        WALLET,
        reason="TEST_WARNING"
    )

    report = audit.generate_report()

    assert report["total_events"] == 4
    assert report["authentication_success"] == 1
    assert report["authentication_failed"] == 1
    assert report["replay_attempts"] == 1
    assert report["security_warnings"] == 1
    assert report["status"] == "AUDIT_READY"


def test_invalid_event_type_is_rejected(audit):
    with pytest.raises(ValueError):
        audit.record_event(
            "UNKNOWN_EVENT"
        )


def test_invalid_details_are_rejected(audit):
    with pytest.raises(ValueError):
        audit.record_event(
            "SECURITY_WARNING",
            details="invalid details"
        )


def test_invalid_wallet_event_limit_is_rejected(audit):
    with pytest.raises(ValueError):
        audit.get_wallet_events(
            WALLET,
            limit=0
        )
