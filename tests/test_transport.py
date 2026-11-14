"""Tests for VOIN Network Transport Engine V1.0."""

import socket

import pytest

from security.communication import VOINCommunicationEngine
from security.network import VOINNetworkSecurityEngine
from security.transport import VOINTransportEngine


LOCAL_ID = "0x" + "1" * 40
REMOTE_ID = "0x" + "2" * 40


def build_engine():
    network = VOINNetworkSecurityEngine()
    assert network.register_peer(
        LOCAL_ID, "http://127.0.0.1:8001"
    )["success"]
    assert network.register_peer(
        REMOTE_ID, "http://127.0.0.1:8002"
    )["success"]

    communication = VOINCommunicationEngine(
        network_engine=network
    )
    transport = VOINTransportEngine(
        communication_engine=communication,
        local_peer_id=LOCAL_ID
    )
    return network, communication, transport


def test_engine_creation_and_info():
    _, _, transport = build_engine()
    info = transport.engine_info()

    assert info["version"] == "1.0.0"
    assert info["transport"] == "TCP"
    assert info["loopback_only"] is True
    assert info["server_running"] is False


def test_requires_communication_engine():
    with pytest.raises(ValueError):
        VOINTransportEngine(None, LOCAL_ID)


def test_start_server_and_stop_server():
    _, _, transport = build_engine()

    started = transport.start_server()

    assert started["success"] is True
    assert started["host"] == "127.0.0.1"
    assert isinstance(started["port"], int)
    assert started["port"] > 0
    assert transport.engine_info()["server_running"] is True

    stopped = transport.stop_server()

    assert stopped["success"] is True
    assert stopped["status"] == "STOPPED"
    assert transport.engine_info()["server_running"] is False


def test_duplicate_server_start_is_rejected():
    _, _, transport = build_engine()

    first = transport.start_server()
    second = transport.start_server()

    assert first["success"] is True
    assert second["success"] is False
    assert transport.stop_server()["success"] is True


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.1", "example.com"])
def test_server_rejects_non_loopback_host(host):
    _, _, transport = build_engine()

    result = transport.start_server(host=host, port=0)

    assert result["success"] is False


@pytest.mark.parametrize("port", [-1, 65536, True, "8080"])
def test_server_rejects_invalid_port(port):
    _, _, transport = build_engine()

    result = transport.start_server(port=port)

    assert result["success"] is False


def test_stop_server_is_idempotent():
    _, _, transport = build_engine()

    assert transport.stop_server()["success"] is True
    assert transport.stop_server()["success"] is True


def test_send_rejects_non_loopback_destination():
    _, _, transport = build_engine()

    result = transport.send_message(
        "192.0.2.1", 9000, {}
    )

    assert result["success"] is False


def test_send_rejects_invalid_port():
    _, _, transport = build_engine()

    result = transport.send_message(
        "127.0.0.1", 0, {}
    )

    assert result["success"] is False


def test_send_rejects_invalid_message():
    _, _, transport = build_engine()

    result = transport.send_message(
        "127.0.0.1", 9000, {"invalid": True}
    )

    assert result["success"] is False
    assert result["error"] == "Message validation failed"


def test_send_reports_connection_failure():
    _, communication, transport = build_engine()
    message = communication.create_message(
        REMOTE_ID,
        LOCAL_ID,
        "PING",
        {}
    )["message"]

    # Bind an ephemeral port and close it so no service is listening.
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        unused_port = sock.getsockname()[1]

    result = transport.send_message(
        "127.0.0.1", unused_port, message
    )

    assert result["success"] is False
    assert result["error"] == "Transport connection failed"


def test_transport_server_receives_message():
    _, communication, transport = build_engine()
    received = []

    assert communication.register_handler(
        "PING",
        lambda payload: received.append(payload) or {"pong": True}
    )

    started = transport.start_server()
    assert started["success"] is True

    try:
        message = communication.create_message(
            REMOTE_ID,
            LOCAL_ID,
            "PING",
            {"probe": "local-test"}
        )
        assert message["success"] is True

        # The sender-side validator and receiver-side server use the
        # same local test network in this unit test.
        result = transport.send_message(
            "127.0.0.1",
            started["port"],
            message["message"]
        )

        assert result["success"] is True
        assert result["result"] == {"pong": True}
        assert received == [{"probe": "local-test"}]
    finally:
        transport.stop_server()
