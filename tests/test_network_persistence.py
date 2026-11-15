"""
VOIN NETWORK PERSISTENCE TEST SUITE V1.1

Tests:
- Peer persistence
- Peer retrieval
- Peer listing
- Peer revocation
- Persistence after engine restart
- Network security event logging
- Invalid input handling
- Duplicate peer registration
- Atomic peer registration
- Atomic peer revocation
- Repeated revocation protection
- Shared in-memory database
- SQLite connection lifecycle
- Network event consistency
"""

import json
import sqlite3

import pytest

from security.storage import VOINStorageEngine


@pytest.fixture
def database_path(tmp_path):
    return tmp_path / "voin_network_test.db"


@pytest.fixture
def storage(database_path):
    return VOINStorageEngine(database_path)


@pytest.fixture
def peer():
    return {
        "peer_id": "0x1234567890abcdef1234567890abcdef12345678",
        "endpoint": "https://node1.voin.network:8080"
    }


# ==================================================
# VERSION
# ==================================================

def test_storage_engine_version():
    assert VOINStorageEngine.VERSION == "1.3.0"


# ==================================================
# BASIC PEER PERSISTENCE
# ==================================================

def test_save_network_peer(storage, peer):

    result = storage.save_network_peer(
        peer["peer_id"],
        peer["endpoint"]
    )

    assert result is True


def test_get_network_peer(storage, peer):

    storage.save_network_peer(
        peer["peer_id"],
        peer["endpoint"]
    )

    result = storage.get_network_peer(
        peer["peer_id"]
    )

    assert result is not None
    assert result["peer_id"] == peer["peer_id"]
    assert result["endpoint"] == peer["endpoint"]
    assert result["status"] == "TRUSTED"


def test_list_network_peers(storage, peer):

    storage.save_network_peer(
        peer["peer_id"],
        peer["endpoint"]
    )

    peers = storage.list_network_peers()

    assert len(peers) == 1
    assert peers[0]["peer_id"] == peer["peer_id"]


def test_list_trusted_network_peers(storage, peer):

    storage.save_network_peer(
        peer["peer_id"],
        peer["endpoint"]
    )

    peers = storage.list_network_peers(
        status="TRUSTED"
    )

    assert len(peers) == 1
    assert peers[0]["status"] == "TRUSTED"


# ==================================================
# PEER REVOCATION
# ==================================================

def test_revoke_network_peer(storage, peer):

    storage.save_network_peer(
        peer["peer_id"],
        peer["endpoint"]
    )

    result = storage.revoke_network_peer(
        peer["peer_id"]
    )

    assert result is True

    saved_peer = storage.get_network_peer(
        peer["peer_id"]
    )

    assert saved_peer["status"] == "REVOKED"


def test_revoked_peer_not_in_trusted_list(storage, peer):

    storage.save_network_peer(
        peer["peer_id"],
        peer["endpoint"]
    )

    storage.revoke_network_peer(
        peer["peer_id"]
    )

    trusted = storage.list_network_peers(
        status="TRUSTED"
    )

    assert trusted == []


def test_revoked_peer_in_revoked_list(storage, peer):

    storage.save_network_peer(
        peer["peer_id"],
        peer["endpoint"]
    )

    storage.revoke_network_peer(
        peer["peer_id"]
    )

    revoked = storage.list_network_peers(
        status="REVOKED"
    )

    assert len(revoked) == 1


def test_repeated_revocation_does_not_duplicate_event(
    storage,
    peer
):

    storage.save_network_peer(
        peer["peer_id"],
        peer["endpoint"]
    )

    first = storage.revoke_network_peer(
        peer["peer_id"]
    )

    second = storage.revoke_network_peer(
        peer["peer_id"]
    )

    assert first is True
    assert second is False

    events = storage.get_network_security_events()

    revoked_events = [
        event for event in events
        if event["event_type"] == "PEER_REVOKED"
    ]

    assert len(revoked_events) == 1


# ==================================================
# DUPLICATE PEER PROTECTION
# ==================================================

def test_duplicate_peer_registration_rejected(
    storage,
    peer
):

    storage.save_network_peer(
        peer["peer_id"],
        peer["endpoint"]
    )

    with pytest.raises(sqlite3.IntegrityError):

        storage.save_network_peer(
            peer["peer_id"],
            "https://different.voin.network:8080"
        )

    saved_peer = storage.get_network_peer(
        peer["peer_id"]
    )

    assert saved_peer["endpoint"] == peer["endpoint"]

    events = storage.get_network_security_events()

    registered_events = [
        event for event in events
        if event["event_type"] == "PEER_REGISTERED"
    ]

    assert len(registered_events) == 1


# ==================================================
# ATOMIC REGISTRATION
# ==================================================

def test_registration_rollback_when_event_fails(
    storage,
    peer
):

    with storage._connect() as connection:

        connection.execute("""
            CREATE TRIGGER fail_peer_registered_event
            BEFORE INSERT ON network_security_events
            WHEN NEW.event_type = 'PEER_REGISTERED'
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'forced registration event failure'
                );
            END;
        """)

    with pytest.raises(sqlite3.IntegrityError):

        storage.save_network_peer(
            peer["peer_id"],
            peer["endpoint"]
        )

    saved_peer = storage.get_network_peer(
        peer["peer_id"]
    )

    assert saved_peer is None

    events = storage.get_network_security_events()

    assert not any(
        event["event_type"] == "PEER_REGISTERED"
        for event in events
    )


# ==================================================
# ATOMIC REVOCATION
# ==================================================

def test_revocation_rollback_when_event_fails(
    storage,
    peer
):

    storage.save_network_peer(
        peer["peer_id"],
        peer["endpoint"]
    )

    with storage._connect() as connection:

        connection.execute("""
            CREATE TRIGGER fail_peer_revoked_event
            BEFORE INSERT ON network_security_events
            WHEN NEW.event_type = 'PEER_REVOKED'
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'forced revocation event failure'
                );
            END;
        """)

    with pytest.raises(sqlite3.IntegrityError):

        storage.revoke_network_peer(
            peer["peer_id"]
        )

    saved_peer = storage.get_network_peer(
        peer["peer_id"]
    )

    assert saved_peer["status"] == "TRUSTED"

    events = storage.get_network_security_events()

    assert not any(
        event["event_type"] == "PEER_REVOKED"
        for event in events
    )


# ==================================================
# DATABASE RESTART PERSISTENCE
# ==================================================

def test_peer_persistence_after_restart(
    database_path,
    peer
):

    storage1 = VOINStorageEngine(database_path)

    storage1.save_network_peer(
        peer["peer_id"],
        peer["endpoint"]
    )

    storage2 = VOINStorageEngine(database_path)

    result = storage2.get_network_peer(
        peer["peer_id"]
    )

    assert result is not None
    assert result["status"] == "TRUSTED"


def test_revocation_persistence_after_restart(
    database_path,
    peer
):

    storage1 = VOINStorageEngine(database_path)

    storage1.save_network_peer(
        peer["peer_id"],
        peer["endpoint"]
    )

    storage1.revoke_network_peer(
        peer["peer_id"]
    )

    storage2 = VOINStorageEngine(database_path)

    result = storage2.get_network_peer(
        peer["peer_id"]
    )

    assert result["status"] == "REVOKED"


# ==================================================
# NETWORK EVENT PERSISTENCE
# ==================================================

def test_network_registration_event(storage, peer):

    storage.save_network_peer(
        peer["peer_id"],
        peer["endpoint"]
    )

    events = storage.get_network_security_events()

    assert any(
        event["event_type"] == "PEER_REGISTERED"
        for event in events
    )


def test_network_revocation_event(storage, peer):

    storage.save_network_peer(
        peer["peer_id"],
        peer["endpoint"]
    )

    storage.revoke_network_peer(
        peer["peer_id"]
    )

    events = storage.get_network_security_events()

    assert any(
        event["event_type"] == "PEER_REVOKED"
        for event in events
    )


def test_log_network_event(storage, peer):

    result = storage.log_network_event(
        "PEER_CONNECTION_REJECTED",
        peer["peer_id"],
        {"reason": "untrusted peer"}
    )

    assert result is True

    events = storage.get_network_security_events()

    assert events[0]["event_type"] == "PEER_CONNECTION_REJECTED"


def test_network_event_details_persistence(storage, peer):

    details = {
        "reason": "untrusted peer",
        "severity": "HIGH"
    }

    storage.log_network_event(
        "PEER_CONNECTION_REJECTED",
        peer["peer_id"],
        details
    )

    events = storage.get_network_security_events()

    saved_details = json.loads(
        events[0]["details"]
    )

    assert saved_details == details


# ==================================================
# UNKNOWN PEER HANDLING
# ==================================================

def test_get_unknown_peer(storage):

    result = storage.get_network_peer(
        "unknown-peer"
    )

    assert result is None


def test_revoke_unknown_peer(storage):

    result = storage.revoke_network_peer(
        "unknown-peer"
    )

    assert result is False


# ==================================================
# INPUT VALIDATION
# ==================================================

def test_invalid_peer_id(storage):

    with pytest.raises(ValueError):

        storage.save_network_peer(
            "",
            "https://node1.voin.network"
        )


def test_invalid_endpoint(storage):

    with pytest.raises(ValueError):

        storage.save_network_peer(
            "peer-001",
            ""
        )


def test_invalid_network_event_type(storage):

    with pytest.raises(ValueError):

        storage.log_network_event(
            "",
            "peer-001"
        )


def test_invalid_network_event_limit(storage):

    with pytest.raises(ValueError):

        storage.get_network_security_events(0)


def test_invalid_network_peer_status(storage):

    with pytest.raises(ValueError):

        storage.list_network_peers(
            status="UNKNOWN"
        )


# ==================================================
# IN-MEMORY DATABASE
# ==================================================

def test_shared_in_memory_database():

    storage = VOINStorageEngine(":memory:")

    try:

        peer_id = "memory-peer-001"
        endpoint = "https://memory.voin.network"

        storage.save_network_peer(
            peer_id,
            endpoint
        )

        result = storage.get_network_peer(
            peer_id
        )

        assert result is not None
        assert result["endpoint"] == endpoint

        events = storage.get_network_security_events()

        assert any(
            event["event_type"] == "PEER_REGISTERED"
            for event in events
        )

    finally:

        storage.close()


def test_in_memory_close_is_idempotent():

    storage = VOINStorageEngine(":memory:")

    storage.close()
    storage.close()


# ==================================================
# CONNECTION LIFECYCLE
# ==================================================

def test_connection_closes_after_context_exit(storage):

    connection = storage._connect()

    with connection as managed_connection:

        result = managed_connection.execute(
            "SELECT 1"
        ).fetchone()

        assert result[0] == 1

    with pytest.raises(sqlite3.ProgrammingError):

        connection.execute(
            "SELECT 1"
        )


# ==================================================
# ENGINE INFORMATION
# ==================================================

def test_engine_info_network_persistence():

    info = VOINStorageEngine.engine_info()

    assert info["persistent_network_peers"] is True
    assert info["persistent_network_events"] is True
    assert info["private_key_storage"] is False
