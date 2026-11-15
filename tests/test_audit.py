"""
VOIN SECURITY AUDIT ENGINE TESTS V1.1.0
"""
import pytest
from security.audit import VOINAuditEngine
from security.storage import VOINStorageEngine
WALLET = "0x1234567890abcdef1234567890abcdef12345678"
OTHER_WALLET = (
"0xabcdef1234567890abcdef1234567890abcdef12"
)
--------------------------------------------------
FIXTURES
--------------------------------------------------
@pytest.fixture
def storage(tmp_path):
engine = VOINStorageEngine(
    str(tmp_path / "audit_test.db")
)

yield engine

engine.close()

@pytest.fixture
def audit(storage):
return VOINAuditEngine(storage=storage)

--------------------------------------------------
ENGINE INFORMATION
--------------------------------------------------
def test_engine_info(audit):
info = audit.engine_info()

assert info["version"] == "1.1.0"
assert info["event_recording"] is True
assert info["wallet_audit_history"] is True
assert info["challenge_tracking"] is True
assert info["nonce_tracking"] is True
assert info["rate_limit_tracking"] is True
assert info["security_reporting"] is True

--------------------------------------------------
EXISTING EVENT COMPATIBILITY
--------------------------------------------------
def test_record_authentication_success(audit):
result = audit.record_authentication_success(
    WALLET,
    "challenge_001"
)

assert result is True

events = audit.get_events()

assert events[0]["event_type"] == (
    "AUTHENTICATION_SUCCESS"
)

def test_record_authentication_failure(audit):
result = audit.record_authentication_failure(
    WALLET,
    "challenge_002",
    "INVALID_SIGNATURE"
)

assert result is True

events = audit.get_events()

assert events[0]["event_type"] == (
    "AUTHENTICATION_FAILED"
)

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

--------------------------------------------------
CHALLENGE EVENTS
--------------------------------------------------
def test_record_challenge_created(audit):
audit.record_challenge_created(
    WALLET,
    "challenge_010"
)

events = audit.get_events()

assert events[0]["event_type"] == "CHALLENGE_CREATED"

def test_record_challenge_consumed(audit):
audit.record_challenge_consumed(
    WALLET,
    "challenge_011"
)

events = audit.get_events()

assert events[0]["event_type"] == "CHALLENGE_CONSUMED"

def test_record_invalid_challenge(audit):
audit.record_invalid_challenge(
    WALLET,
    "challenge_012",
    "CHALLENGE_NOT_FOUND"
)

events = audit.get_events()

assert events[0]["event_type"] == "INVALID_CHALLENGE"

def test_record_expired_challenge(audit):
audit.record_expired_challenge(
    WALLET,
    "challenge_013"
)

events = audit.get_events()

assert events[0]["event_type"] == "EXPIRED_CHALLENGE"

--------------------------------------------------
NONCE EVENTS
--------------------------------------------------
def test_record_nonce_created(audit):
audit.record_nonce_created(WALLET)

events = audit.get_events()

assert events[0]["event_type"] == "NONCE_CREATED"

def test_record_nonce_consumed(audit):
audit.record_nonce_consumed(WALLET)

events = audit.get_events()

assert events[0]["event_type"] == "NONCE_CONSUMED"

def test_record_invalid_nonce(audit):
audit.record_invalid_nonce(
    WALLET,
    reason="NONCE_MISMATCH"
)

events = audit.get_events()

assert events[0]["event_type"] == "INVALID_NONCE"

--------------------------------------------------
AUTHENTICATION CONSUMPTION
--------------------------------------------------
def test_record_authentication_consumed(audit):
audit.record_authentication_consumed(
    WALLET,
    "challenge_014"
)

events = audit.get_events()

assert events[0]["event_type"] == (
    "AUTHENTICATION_CONSUMED"
)

--------------------------------------------------
RATE LIMIT EVENTS
--------------------------------------------------
def test_record_rate_limit_exceeded(audit):
audit.record_rate_limit_exceeded(
    WALLET,
    details={
        "attempts": 6,
        "threshold": 5
    }
)

events = audit.get_events()

assert events[0]["event_type"] == (
    "RATE_LIMIT_EXCEEDED"
)

def test_rate_limit_details_are_persisted(audit):
audit.record_rate_limit_exceeded(
    WALLET,
    details={
        "attempts": 7
    }
)

events = audit.get_events()

assert '"attempts": 7' in events[0]["details"]

def test_invalid_rate_limit_details_are_rejected(audit):
with pytest.raises(ValueError):

    audit.record_rate_limit_exceeded(
        WALLET,
        details="invalid"
    )

--------------------------------------------------
ACCESS CONTROL EVENTS
--------------------------------------------------
def test_record_unauthorized_access(audit):
audit.record_unauthorized_access(
    WALLET,
    reason="ACCESS_DENIED"
)

events = audit.get_events()

assert events[0]["event_type"] == (
    "UNAUTHORIZED_ACCESS"
)

--------------------------------------------------
WALLET HISTORY
--------------------------------------------------
def test_wallet_audit_history(audit):
audit.record_authentication_success(
    WALLET,
    "challenge_020"
)

audit.record_authentication_failure(
    OTHER_WALLET,
    "challenge_021"
)

events = audit.get_wallet_events(WALLET)

assert len(events) == 1

assert events[0]["event_type"] == (
    "AUTHENTICATION_SUCCESS"
)

--------------------------------------------------
REPORTING
--------------------------------------------------
def test_generate_report(audit):
audit.record_authentication_success(
    WALLET,
    "challenge_030"
)

audit.record_authentication_failure(
    WALLET,
    "challenge_031"
)

audit.record_replay_attempt(
    WALLET,
    "challenge_032"
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

def test_report_counts_all_new_events(audit):
audit.record_rate_limit_exceeded(WALLET)

audit.record_invalid_challenge(WALLET)

audit.record_invalid_nonce(WALLET)

audit.record_expired_challenge(WALLET)

audit.record_unauthorized_access(WALLET)

report = audit.generate_report()

assert report["total_events"] == 5

assert report["rate_limit_exceeded"] == 1
assert report["invalid_challenges"] == 1
assert report["invalid_nonces"] == 1
assert report["expired_challenges"] == 1
assert report["unauthorized_access"] == 1

def test_report_counts_persistence_events(audit):
audit.record_challenge_created(
    WALLET,
    "challenge_040"
)

audit.record_challenge_consumed(
    WALLET,
    "challenge_041"
)

audit.record_nonce_created(WALLET)

audit.record_nonce_consumed(WALLET)

report = audit.generate_report()

assert report["challenges_created"] == 1
assert report["challenges_consumed"] == 1
assert report["nonces_created"] == 1
assert report["nonces_consumed"] == 1

--------------------------------------------------
VALIDATION
--------------------------------------------------
@pytest.mark.parametrize(
"event_type",
[
"UNKNOWN_EVENT",
"",
None,
123,
[],
{}
]
)
def test_invalid_event_type_is_rejected(
audit,
event_type
):
with pytest.raises(ValueError):

    audit.record_event(event_type)

@pytest.mark.parametrize(
"details",
[
"invalid",
[],
123,
True
]
)
def test_invalid_details_are_rejected(
audit,
details
):
with pytest.raises(ValueError):

    audit.record_event(
        "SECURITY_WARNING",
        details=details
    )

@pytest.mark.parametrize(
"limit",
[
0,
-1,
1.5,
"100",
True,
None
]
)
def test_invalid_event_limit_is_rejected(
audit,
limit
):
with pytest.raises(ValueError):

    audit.get_events(limit=limit)

def test_invalid_wallet_event_limit_is_rejected(audit):
with pytest.raises(ValueError):

    audit.get_wallet_events(
        WALLET,
        limit=0
    )

def test_invalid_wallet_address_is_rejected(audit):
with pytest.raises(ValueError):

    audit.get_wallet_events(
        "",
        limit=10
    )

--------------------------------------------------
UNKNOWN EVENT REPORTING
--------------------------------------------------
def test_unknown_storage_event_is_reported_as_other(audit):
audit.storage.log_event(
    event_type="FUTURE_SECURITY_EVENT",
    wallet_address=WALLET
)

report = audit.generate_report()

assert report["total_events"] == 1
assert report["other_events"] == 1

--------------------------------------------------
EVENT RETRIEVAL LIMIT
--------------------------------------------------
def test_get_events_respects_limit(audit):
for index in range(5):

    audit.record_security_warning(
        WALLET,
        reason=f"WARNING_{index}"
    )

events = audit.get_events(limit=2)

assert len(events) == 2

def test_get_wallet_events_respects_limit(audit):
for index in range(5):

    audit.record_security_warning(
        WALLET,
        reason=f"WARNING_{index}"
    )

events = audit.get_wallet_events(
    WALLET,
    limit=2
)

assert len(events) == 2

