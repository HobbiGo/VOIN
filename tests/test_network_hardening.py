"""
VOIN NETWORK SECURITY HARDENING TEST SUITE V1.0

Tests:
- Peer recovery after restart
- Revoked peer persistence
- Duplicate registration prevention
- Revoked peer re-registration prevention
- Memory and database consistency
- Persistent network event logging
- Peer status consistency
"""

import pytest

from security.network import VOINNetworkSecurityEngine
from security.storage import VOINStorageEngine


@pytest.fixture
def database_path(tmp_path):
    return tmp_path / "voin_network_hardening.db"


@pytest.fixture
def storage(database_path):
    return VOINStorageEngine(database_path)


@pytest.fixture
def peer_id():
    return "0x1234567890abcdef1234567890abcdef12345678"


@pytest.fixture
def endpoint():
    return "https://node1.voin.network:8080"


@pytest.fixture
def engine(storage):
    return VOINNetworkSecurityEngine(
        storage_engine=storage
    )


# --------------------------------------------------
# ENGINE INTEGRATION
# --------------------------------------------------

def test_engine_uses_persistent_storage(engine):

    info = engine.engine_info()

    assert info["persistent_peer_storage"] is True
    assert info["peer_recovery"] is True


def test_engine_version(engine):

    assert engine.VERSION == "1.1.0"


# --------------------------------------------------
# PEER PERSISTENCE
# --------------------------------------------------

def test_registered_peer_saved_to_database(
    engine,
    storage,
    peer_id,
    endpoint
):

    result = engine.register_peer(
        peer_id,
        endpoint
    )

    assert result["success"] is True

    saved = storage.get_network_peer(peer_id)

    assert saved is not None
    assert saved["status"] == "TRUSTED"
    assert saved["endpoint"] == endpoint


def test_peer_recovered_after_restart(
    database_path,
    peer_id,
    endpoint
):

    storage1 = VOINStorageEngine(database_path)

    engine1 = VOINNetworkSecurityEngine(
        storage_engine=storage1
    )

    engine1.register_peer(
        peer_id,
        endpoint
    )

    storage2 = VOINStorageEngine(database_path)

    engine2 = VOINNetworkSecurityEngine(
        storage_engine=storage2
    )

    assert engine2.is_trusted_peer(peer_id) is True


def test_revoked_peer_stays_revoked_after_restart(
    database_path,
    peer_id,
    endpoint
):

    storage1 = VOINStorageEngine(database_path)

    engine1 = VOINNetworkSecurityEngine(
        storage_engine=storage1
    )

    engine1.register_peer(
        peer_id,
        endpoint
    )

    engine1.revoke_peer(peer_id)

    storage2 = VOINStorageEngine(database_path)

    engine2 = VOINNetworkSecurityEngine(
        storage_engine=storage2
    )

    assert engine2.is_trusted_peer(peer_id) is False

    peer = engine2.get_peer(peer_id)

    assert peer["status"] == "REVOKED"


# --------------------------------------------------
# DUPLICATE REGISTRATION
# --------------------------------------------------

def test_duplicate_registration_rejected(
    engine,
    peer_id,
    endpoint
):

    first = engine.register_peer(
        peer_id,
        endpoint
    )

    second = engine.register_peer(
        peer_id,
        endpoint
    )

    assert first["success"] is True
    assert second["success"] is False


def test_duplicate_registration_does_not_change_endpoint(
    engine,
    peer_id,
    endpoint
):

    engine.register_peer(
        peer_id,
        endpoint
    )

    result = engine.register_peer(
        peer_id,
        "https://another-node.voin.network"
    )

    assert result["success"] is False

    peer = engine.get_peer(peer_id)

    assert peer["endpoint"] == endpoint


def test_revoked_peer_cannot_be_registered_again(
    engine,
    peer_id,
    endpoint
):

    engine.register_peer(
        peer_id,
        endpoint
    )

    engine.revoke_peer(peer_id)

    result = engine.register_peer(
        peer_id,
        endpoint
    )

    assert result["success"] is False

    peer = engine.get_peer(peer_id)

    assert peer["status"] == "REVOKED"


# --------------------------------------------------
# MEMORY AND DATABASE CONSISTENCY
# --------------------------------------------------

def test_peer_status_matches_database(
    engine,
    storage,
    peer_id,
    endpoint
):

    engine.register_peer(
        peer_id,
        endpoint
    )

    memory_peer = engine.get_peer(peer_id)
    database_peer = storage.get_network_peer(peer_id)

    assert memory_peer["status"] == database_peer["status"]


def test_revocation_matches_database(
    engine,
    storage,
    peer_id,
    endpoint
):

    engine.register_peer(
        peer_id,
        endpoint
    )

    engine.revoke_peer(peer_id)

    memory_peer = engine.get_peer(peer_id)
    database_peer = storage.get_network_peer(peer_id)

    assert memory_peer["status"] == "REVOKED"
    assert database_peer["status"] == "REVOKED"


def test_revoked_peer_not_in_trusted_status(
    engine,
    peer_id,
    endpoint
):

    engine.register_peer(
        peer_id,
        endpoint
    )

    engine.revoke_peer(peer_id)

    assert engine.is_trusted_peer(peer_id) is False


# --------------------------------------------------
# NETWORK EVENT PERSISTENCE
# --------------------------------------------------

def test_registration_event_persisted(
    engine,
    storage,
    peer_id,
    endpoint
):

    engine.register_peer(
        peer_id,
        endpoint
    )

    events = storage.get_network_security_events()

    assert any(
        event["event_type"] == "PEER_REGISTERED"
        and event["peer_id"] == peer_id
        for event in events
    )


def test_revocation_event_persisted(
    engine,
    storage,
    peer_id,
    endpoint
):

    engine.register_peer(
        peer_id,
        endpoint
    )

    engine.revoke_peer(peer_id)

    events = storage.get_network_security_events()

    assert any(
        event["event_type"] == "PEER_REVOKED"
        and event["peer_id"] == peer_id
        for event in events
    )


def test_registration_event_not_duplicated(
    engine,
    storage,
    peer_id,
    endpoint
):

    engine.register_peer(
        peer_id,
        endpoint
    )

    events = storage.get_network_security_events()

    registration_events = [
        event
        for event in events
        if event["event_type"] == "PEER_REGISTERED"
        and event["peer_id"] == peer_id
    ]

    assert len(registration_events) == 1


def test_revocation_event_not_duplicated(
    engine,
    storage,
    peer_id,
    endpoint
):

    engine.register_peer(
        peer_id,
        endpoint
    )

    engine.revoke_peer(peer_id)

    events = storage.get_network_security_events()

    revocation_events = [
        event
        for event in events
        if event["event_type"] == "PEER_REVOKED"
        and event["peer_id"] == peer_id
    ]

    assert len(revocation_events) == 1


# --------------------------------------------------
# PEER LIST CONSISTENCY
# --------------------------------------------------

def test_list_peers_includes_revoked_peer(
    engine,
    peer_id,
    endpoint
):

    engine.register_peer(
        peer_id,
        endpoint
    )

    engine.revoke_peer(peer_id)

    peers = engine.list_peers()

    assert len(peers) == 1
    assert peers[0]["status"] == "REVOKED"


def test_unknown_peer_is_not_trusted(engine):

    assert engine.is_trusted_peer(
        "unknown-peer"
    ) is False


# --------------------------------------------------
# STORAGE RECOVERY
# --------------------------------------------------

def test_multiple_peers_recovered_after_restart(
    database_path
):

    peer1 = "0x1111111111111111111111111111111111111111"
    peer2 = "0x2222222222222222222222222222222222222222"

    storage1 = VOINStorageEngine(database_path)

    engine1 = VOINNetworkSecurityEngine(
        storage_engine=storage1
    )

    engine1.register_peer(
        peer1,
        "https://node1.voin.network"
    )

    engine1.register_peer(
        peer2,
        "https://node2.voin.network"
    )

    storage2 = VOINStorageEngine(database_path)

    engine2 = VOINNetworkSecurityEngine(
        storage_engine=storage2
    )

    assert engine2.is_trusted_peer(peer1) is True
    assert engine2.is_trusted_peer(peer2) is True

    assert len(engine2.list_peers()) == 2
