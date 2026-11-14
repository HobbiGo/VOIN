"""
VOIN NETWORK SECURITY TEST SUITE V1.0
"""

import pytest

from security.network import VOINNetworkSecurityEngine


@pytest.fixture
def engine():
    return VOINNetworkSecurityEngine()


@pytest.fixture
def peer_id():
    return "0x1234567890123456789012345678901234567890"


@pytest.fixture
def endpoint():
    return "https://node.voin.network:8080"


def test_engine_creation(engine):

    assert engine.VERSION == "1.0.0"
    assert engine.trusted_peers == {}
    assert engine.security_events == []


@pytest.mark.parametrize(
    "peer_id",
    [
        "invalid",
        "",
        None,
        123,
        "0x1234",
        "0x123456789012345678901234567890123456789g"
    ]
)
def test_invalid_peer_identity(engine, peer_id):

    assert engine.validate_peer_identity(peer_id) is False


def test_valid_peer_identity(engine, peer_id):

    assert engine.validate_peer_identity(peer_id) is True


@pytest.mark.parametrize(
    "endpoint",
    [
        "",
        "invalid",
        None,
        "ftp://node.voin.network",
        "https://",
        "https://user:password@node.voin.network",
        "https://node.voin.network:99999",
        "https://node.voin.network/path",
        "https://node.voin.network?token=test",
        "https://node.voin.network#fragment",
        " https://node.voin.network"
    ]
)
def test_invalid_endpoint(engine, endpoint):

    assert engine.validate_endpoint(endpoint) is False


def test_valid_endpoint(engine, endpoint):

    assert engine.validate_endpoint(endpoint) is True


def test_register_peer(engine, peer_id, endpoint):

    result = engine.register_peer(
        peer_id,
        endpoint
    )

    assert result["success"] is True
    assert result["status"] == "TRUSTED"
    assert engine.is_trusted_peer(peer_id) is True


def test_duplicate_peer_registration(
    engine,
    peer_id,
    endpoint
):

    engine.register_peer(peer_id, endpoint)

    result = engine.register_peer(
        peer_id,
        endpoint
    )

    assert result["success"] is False
    assert result["error"] == "Peer already registered"


def test_reject_invalid_peer_registration(
    engine,
    endpoint
):

    result = engine.register_peer(
        "invalid-peer",
        endpoint
    )

    assert result["success"] is False
    assert engine.trusted_peers == {}


def test_reject_invalid_endpoint_registration(
    engine,
    peer_id
):

    result = engine.register_peer(
        peer_id,
        "invalid-endpoint"
    )

    assert result["success"] is False
    assert engine.trusted_peers == {}


def test_revoke_peer(engine, peer_id, endpoint):

    engine.register_peer(peer_id, endpoint)

    result = engine.revoke_peer(peer_id)

    assert result["success"] is True
    assert result["status"] == "REVOKED"
    assert engine.is_trusted_peer(peer_id) is False


def test_revoke_unknown_peer(engine):

    result = engine.revoke_peer(
        "0x1234567890123456789012345678901234567890"
    )

    assert result["success"] is False


def test_get_peer(engine, peer_id, endpoint):

    engine.register_peer(peer_id, endpoint)

    peer = engine.get_peer(peer_id)

    assert peer is not None
    assert peer["peer_id"] == peer_id
    assert peer["endpoint"] == endpoint


def test_get_unknown_peer(engine):

    assert engine.get_peer(
        "0x1234567890123456789012345678901234567890"
    ) is None


def test_list_peers(engine, peer_id, endpoint):

    engine.register_peer(peer_id, endpoint)

    peers = engine.list_peers()

    assert len(peers) == 1
    assert peers[0]["peer_id"] == peer_id


def test_security_event_logging(
    engine,
    peer_id,
    endpoint
):

    engine.register_peer(peer_id, endpoint)

    events = engine.get_security_events()

    assert len(events) == 1
    assert events[0]["event_type"] == "PEER_REGISTERED"


def test_invalid_identity_event(engine):

    engine.register_peer(
        "invalid",
        "https://node.voin.network"
    )

    events = engine.get_security_events()

    assert events[0]["event_type"] == "INVALID_PEER_IDENTITY"


def test_duplicate_peer_event(engine, peer_id, endpoint):

    engine.register_peer(peer_id, endpoint)
    engine.register_peer(peer_id, endpoint)

    events = engine.get_security_events()

    assert events[-1]["event_type"] == "DUPLICATE_PEER"


def test_engine_info(engine):

    info = engine.engine_info()

    assert info["engine"] == "VOIN Network Security Engine"
    assert info["version"] == "1.0.0"
    assert info["trusted_peer_management"] is True
    assert info["p2p_network"] is False


def test_peer_copy_is_independent(engine, peer_id, endpoint):

    engine.register_peer(peer_id, endpoint)

    peer = engine.get_peer(peer_id)
    peer["status"] = "MODIFIED"

    assert engine.is_trusted_peer(peer_id) is True
