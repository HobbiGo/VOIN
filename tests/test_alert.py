"""
VOIN SECURITY ALERT ENGINE TEST SUITE V1.0

Tests:
- Alert engine creation
- Risk classification
- Persistent alert storage
- Duplicate prevention
- Alert acknowledgment
- Alert resolution
- Alert filtering
- Alert summary
- Event scanning
- Input validation
"""

import pytest

from security.storage import VOINStorageEngine
from security.alert import VOINAlertEngine


@pytest.fixture
def storage(tmp_path):

    database = tmp_path / "voin_alert_test.db"

    return VOINStorageEngine(str(database))


@pytest.fixture
def alert_engine(storage):

    return VOINAlertEngine(storage=storage)


@pytest.fixture
def security_event():

    return {
        "id": 1,
        "event_type": "REPLAY_ATTEMPT",
        "wallet_address": "0x1234567890abcdef",
        "reference_id": "challenge-001"
    }


def test_alert_engine_creation(alert_engine):

    info = alert_engine.engine_info()

    assert info["engine"] == "VOIN Security Alert Engine"
    assert info["version"] == "1.0.0"
    assert info["persistent_alerts"] is True
    assert info["duplicate_prevention"] is True
    assert info["status"] == "READY_FOR_TESTING"


def test_risk_classification(alert_engine):

    assert (
        alert_engine._classify_risk("AUTHENTICATION_SUCCESS")
        == "LOW"
    )

    assert (
        alert_engine._classify_risk("AUTHENTICATION_FAILED")
        == "MEDIUM"
    )

    assert (
        alert_engine._classify_risk("REPLAY_ATTEMPT")
        == "HIGH"
    )

    assert (
        alert_engine._classify_risk("UNAUTHORIZED_ACCESS")
        == "CRITICAL"
    )


def test_process_security_event(
    alert_engine,
    security_event
):

    alert = alert_engine.process_event(security_event)

    assert alert["event_type"] == "REPLAY_ATTEMPT"
    assert alert["risk_level"] == "HIGH"
    assert alert["status"] == "OPEN"
    assert alert["wallet_address"] == (
        "0x1234567890abcdef"
    )


def test_duplicate_alert_prevention(
    alert_engine,
    security_event
):

    first = alert_engine.process_event(security_event)

    second = alert_engine.process_event(security_event)

    assert first["alert_id"] == second["alert_id"]

    alerts = alert_engine.get_alerts()

    assert len(alerts) == 1


def test_acknowledge_alert(
    alert_engine,
    security_event
):

    alert = alert_engine.process_event(security_event)

    result = alert_engine.acknowledge_alert(
        alert["alert_id"]
    )

    assert result is True

    updated = alert_engine.get_alerts(
        status="ACKNOWLEDGED"
    )

    assert len(updated) == 1


def test_resolve_alert(
    alert_engine,
    security_event
):

    alert = alert_engine.process_event(security_event)

    result = alert_engine.resolve_alert(
        alert["alert_id"]
    )

    assert result is True

    updated = alert_engine.get_alerts(
        status="RESOLVED"
    )

    assert len(updated) == 1


def test_alert_filtering(alert_engine):

    alert_engine.process_event({
        "id": 1,
        "event_type": "REPLAY_ATTEMPT",
        "wallet_address": "0x111",
        "reference_id": "ref-001"
    })

    alert_engine.process_event({
        "id": 2,
        "event_type": "UNAUTHORIZED_ACCESS",
        "wallet_address": "0x222",
        "reference_id": "ref-002"
    })

    critical = alert_engine.get_alerts(
        risk_level="CRITICAL"
    )

    high = alert_engine.get_alerts(
        risk_level="HIGH"
    )

    assert len(critical) == 1
    assert len(high) == 1


def test_alert_summary(alert_engine):

    alert_engine.process_event({
        "id": 1,
        "event_type": "REPLAY_ATTEMPT",
        "wallet_address": "0x111",
        "reference_id": "ref-001"
    })

    alert_engine.process_event({
        "id": 2,
        "event_type": "UNAUTHORIZED_ACCESS",
        "wallet_address": "0x222",
        "reference_id": "ref-002"
    })

    summary = alert_engine.get_alert_summary()

    assert summary["total"] == 2
    assert summary["by_risk"]["HIGH"] == 1
    assert summary["by_risk"]["CRITICAL"] == 1
    assert summary["by_status"]["OPEN"] == 2


def test_scan_security_events(storage, alert_engine):

    storage.log_event(
        "REPLAY_ATTEMPT",
        "0x1234567890abcdef",
        "challenge-001"
    )

    alerts = alert_engine.scan_events()

    assert len(alerts) == 1
    assert alerts[0]["event_type"] == "REPLAY_ATTEMPT"


def test_invalid_event_rejected(alert_engine):

    with pytest.raises(ValueError):

        alert_engine.process_event(None)


def test_invalid_event_id_rejected(alert_engine):

    with pytest.raises(ValueError):

        alert_engine.process_event({
            "id": 0,
            "event_type": "REPLAY_ATTEMPT"
        })


def test_invalid_event_type_rejected(alert_engine):

    with pytest.raises(ValueError):

        alert_engine.process_event({
            "id": 1,
            "event_type": ""
        })


def test_invalid_alert_status_rejected(alert_engine):

    with pytest.raises(ValueError):

        alert_engine.get_alerts(
            status="INVALID"
        )


def test_invalid_risk_level_rejected(alert_engine):

    with pytest.raises(ValueError):

        alert_engine.get_alerts(
            risk_level="UNKNOWN"
        )
