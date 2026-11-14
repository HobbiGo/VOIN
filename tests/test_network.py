"""
VOIN NETWORK SECURITY TEST SUITE V1.1

Tests:
- Engine creation
- Engine information
- Peer identity validation
- Endpoint validation
- Peer registration
- Duplicate peer prevention
- Peer revocation
- Trusted peer status
- Peer retrieval
- Peer listing
- Security event logging
"""

import pytest

from security.network import VOINNetworkSecurityEngine


@pytest.fixture
def engine():
    return VOINNetworkSecurityEngine()


@pytest.fixture
def peer_id():
    return "0x1234567890abcdef1234567890abcdef12345678"


@pytest.fixture
def endpoint():
    return "https://node1.voin.network:8080"


# --------------------------------------------------
# ENGINE TESTS
# --------------------------------------------------

def test_engine_creation(engine):

    assert isinstance(
        engine,
        VOINNetworkSecurityEngine
    )

    assert engine.VERSION == "1.1.0"


def test_engine_info(engine):

    info = engine.engine_info()

    assert info["engine"] == "VOIN Network Security Engine"
    assert info["version"] == "1.1.0"

    assert info["peer_identity_validation"] is True
    assert info["trusted_peer_management"] is True
    assert info["endpoint_validation"] is True
    assert info["duplicate_peer_protection"] is True
    assert info["security_event_logging"] is True

    assert info["persistent_peer_storage"] is False
    assert info["peer_recovery"] is False

    assert info["p2p_network"] is False


# --------------------------------------------------
# PEER IDENTITY VALIDATION
# --------------------------------------------------

def test_valid_peer_identity(peer_id):

    assert VOINNetworkSecurityEngine.validate_peer_identity(
        peer_id
    ) is True


@pytest.mark.parametrize(
    "peer_id",
    [
        "",
        "invalid-peer",
        "0x1234",
        "1234567890abcdef1234567890abcdef12345678",
        "0xZZ34567890abcdef1234567890abcdef12345678",
        None,
        12345
    ]
)
def test_invalid_peer_identity(peer_id):

    assert VOINNetworkSecurityEngine.validate_peer_identity(
        peer_id
    ) is False


# --------------------------------------------------
# ENDPOINT VALIDATION
# --------------------------------------------------

@pytest.mark.parametrize(
    "endpoint",
    [
        "https://node1.voin.network",
        "http://127.0.0.1:8080",
        "https://node1.voin.network:443"
    ]
)
def test_valid_endpoint(endpoint):

    assert VOINNetworkSecurityEngine.validate_endpoint(
        endpoint
    ) is True


@pytest.mark.parametrize(
    "endpoint",
    [
        "",
        "ftp://node1.voin.network",
        "https://",
        "https://user:password@node1.voin.network",
        "https://node1.voin.network/path",
        "https://node1.voin.network?query=1",
        "https://node1.voin.network#fragment",
        "https://node1.voin.network:99999",
        "https://node1.voin.network:0",
        " https://node1.voin.network",
        None,
        12345
    ]
)
def test_invalid_endpoint(endpoint):

    assert VOINNetworkSecurityEngine.validate_endpoint(
        endpoint
    ) is False


# --------------------------------------------------
# PEER REGISTRATION
# --------------------------------------------------

def test_register_peer(engine, peer_id, endpoint):

    result = engine.register_peer(
        peer_id,
        endpoint
    )

    assert result["success"] is True
    assert result["peer_id"] == peer_id
    assert result["status"] == "TRUSTED"


def test_registered_peer_exists(engine, peer_id, endpoint):

    engine.register_peer(
        peer_id,
        endpoint
    )

    assert peer_id in engine.trusted_peers


def test_register_invalid_peer(engine, endpoint):

    result = engine.register_peer(
        "invalid-peer",
        endpoint
    )

    assert result["success"] is False
    assert result["error"] == "Invalid peer identity"


def test_register_invalid_endpoint(engine, peer_id):

    result = engine.register_peer(
        peer_id,
        "invalid-endpoint"
    )

    assert result["success"] is False
    assert result["error"] == "Invalid peer endpoint"


def test_duplicate_peer_registration(
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
    assert second["error"] == "Peer already registered"


# --------------------------------------------------
# PEER REVOCATION
# --------------------------------------------------

def test_revoke_peer(engine, peer_id, endpoint):

    engine.register_peer(
        peer_id,
        endpoint
    )

    result = engine.revoke_peer(peer_id)

    assert result["success"] is True
    assert result["status"] == "REVOKED"


def test_revoke_unknown_peer(engine):

    result = engine.revoke_peer(
        "unknown-peer"
    )

    assert result["success"] is False
    assert result["error"] == "Peer not found"


def test_revoked_peer_is_not_trusted(
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


def test_revoked_peer_cannot_be_revoked_again(
    engine,
    peer_id,
    endpoint
):

    engine.register_peer(
        peer_id,
        endpoint
    )

    engine.revoke_peer(peer_id)

    result = engine.revoke_peer(peer_id)

    assert result["success"] is False
    assert result["error"] == "Peer already revoked"


# --------------------------------------------------
# TRUST STATUS
# --------------------------------------------------

def test_is_trusted_peer(engine, peer_id, endpoint):

    engine.register_peer(
        peer_id,
        endpoint
    )

    assert engine.is_trusted_peer(peer_id) is True


def test_unknown_peer_is_not_trusted(engine):

    assert engine.is_trusted_peer(
        "unknown-peer"
    ) is False


# --------------------------------------------------
# PEER RETRIEVAL
# --------------------------------------------------

def test_get_peer(engine, peer_id, endpoint):

    engine.register_peer(
        peer_id,
        endpoint
    )

    peer = engine.get_peer(peer_id)

    assert peer is not None
    assert peer["peer_id"] == peer_id
    assert peer["endpoint"] == endpoint
    assert peer["status"] == "TRUSTED"


def test_get_unknown_peer(engine):

    assert engine.get_peer("unknown-peer") is None


def test_list_peers(engine, peer_id, endpoint):

    engine.register_peer(
        peer_id,
        endpoint
    )

    peers = engine.list_peers()

    assert len(peers) == 1
    assert peers[0]["peer_id"] == peer_id


def test_list_empty_peers(engine):

    assert engine.list_peers() == []


# --------------------------------------------------
# SECURITY EVENT LOGGING
# --------------------------------------------------

def test_peer_registration_event(
    engine,
    peer_id,
    endpoint
):

    engine.register_peer(
        peer_id,
        endpoint
    )

    events = engine.get_security_events()

    assert any(
        event["event_type"] == "PEER_REGISTERED"
        for event in events
    )


def test_peer_revocation_event(
    engine,
    peer_id,
    endpoint
):

    engine.register_peer(
        peer_id,
        endpoint
    )

    engine.revoke_peer(peer_id)

    events = engine.get_security_events()

    assert any(
        event["event_type"] == "PEER_REVOKED"
        for event in events
    )


def test_duplicate_peer_event(
    engine,
    peer_id,
    endpoint
):

    engine.register_peer(
        peer_id,
        endpoint
    )

    engine.register_peer(
        peer_id,
        endpoint
    )

    events = engine.get_security_events()

    assert any(
        event["event_type"] == "DUPLICATE_PEER"
        for event in events
    )


def test_invalid_peer_event(engine, endpoint):

    engine.register_peer(
        "invalid-peer",
        endpoint
    )

    events = engine.get_security_events()

    assert any(
        event["event_type"] == "INVALID_PEER_IDENTITY"
        for event in events
    )


def test_invalid_endpoint_event(engine, peer_id):

    engine.register_peer(
        peer_id,
        "invalid-endpoint"
    )

    events = engine.get_security_events()

    assert any(
        event["event_type"] == "INVALID_PEER_ENDPOINT"
        for event in events
    )


def test_security_event_structure(
    engine,
    peer_id,
    endpoint
):

    engine.register_peer(
        peer_id,
        endpoint
    )

    events = engine.get_security_events()

    event = events[0]

    assert "event_type" in event
    assert "peer_id" in event
    assert "details" in event
    assert "timestamp" in event


# --------------------------------------------------
# EVENT ISOLATION
# --------------------------------------------------

def test_get_security_events_returns_copy(
    engine,
    peer_id,
    endpoint
):

    engine.register_peer(
        peer_id,
        endpoint
    )

    events = engine.get_security_events()

    events.clear()

    assert len(engine.get_security_events()) > 0


# --------------------------------------------------
# ENGINE STATUS
# --------------------------------------------------

def test_engine_status(engine):

    info = engine.engine_info()

    assert info["status"] == "READY_FOR_TESTING"
