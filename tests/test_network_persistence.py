"""
VOIN NETWORK PERSISTENCE TEST SUITE V1.0

Tests:
- Peer persistence
- Peer retrieval
- Peer listing
- Peer revocation
- Persistence after engine restart
- Network security event logging
- Invalid input handling
"""

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


def test_storage_engine_version():
    assert VOINStorageEngine.VERSION == "1.2.0"


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


def test_engine_info_network_persistence():

    info = VOINStorageEngine.engine_info()

    assert info["persistent_network_peers"] is True
    assert info["persistent_network_events"] is True
    assert info["private_key_storage"] is False
