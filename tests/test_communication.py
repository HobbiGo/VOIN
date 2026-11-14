"""
VOIN NETWORK COMMUNICATION ENGINE TEST SUITE V1.0
"""

import time
import uuid

import pytest

from security.network import VOINNetworkSecurityEngine
from security.communication import VOINCommunicationEngine
from security.storage import VOINStorageEngine


@pytest.fixture
def network():
    engine = VOINNetworkSecurityEngine()

    engine.register_peer(
        "0x1234567890abcdef1234567890abcdef12345678",
        "http://127.0.0.1:8001"
    )

    engine.register_peer(
        "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        "http://127.0.0.1:8002"
    )

    return engine


@pytest.fixture
def communication(network):
    return VOINCommunicationEngine(
        network_engine=network
    )


@pytest.fixture
def peer_ids():
    return (
        "0x1234567890abcdef1234567890abcdef12345678",
        "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
    )


@pytest.fixture
def valid_message(communication, peer_ids):

    sender, receiver = peer_ids

    result = communication.create_message(
        sender,
        receiver,
        "PING",
        {"status": "active"}
    )

    assert result["success"] is True

    return result["message"]


# --------------------------------------------------
# ENGINE INITIALIZATION
# --------------------------------------------------

def test_engine_creation(communication):

    assert communication.VERSION == "1.0.0"


def test_engine_info(communication):

    info = communication.engine_info()

    assert info["message_protocol"] is True
    assert info["peer_authorization"] is True
    assert info["message_validation"] is True
    assert info["replay_protection"] is True
    assert info["live_network_transport"] is False


# --------------------------------------------------
# MESSAGE ID VALIDATION
# --------------------------------------------------

def test_valid_message_id(communication):

    assert communication.validate_message_id(
        str(uuid.uuid4())
    )


def test_invalid_message_id(communication):

    assert not communication.validate_message_id(
        "invalid-message-id"
    )


def test_non_string_message_id(communication):

    assert not communication.validate_message_id(123)


# --------------------------------------------------
# PEER AUTHORIZATION
# --------------------------------------------------

def test_authorized_peer(communication, peer_ids):

    assert communication.is_authorized_peer(peer_ids[0])


def test_unauthorized_peer(communication):

    assert not communication.is_authorized_peer(
        "0x9999999999999999999999999999999999999999"
    )


def test_missing_network_engine():

    engine = VOINCommunicationEngine()

    assert not engine.is_authorized_peer(
        "0x1234567890abcdef1234567890abcdef12345678"
    )


# --------------------------------------------------
# MESSAGE CREATION
# --------------------------------------------------

def test_create_valid_message(communication, peer_ids):

    sender, receiver = peer_ids

    result = communication.create_message(
        sender,
        receiver,
        "PING",
        {"status": "active"}
    )

    assert result["success"] is True
    assert result["message"]["message_type"] == "PING"


def test_create_message_unauthorized_sender(
    communication,
    peer_ids
):

    result = communication.create_message(
        "0x9999999999999999999999999999999999999999",
        peer_ids[1],
        "PING",
        {}
    )

    assert result["success"] is False


def test_create_message_unauthorized_receiver(
    communication,
    peer_ids
):

    result = communication.create_message(
        peer_ids[0],
        "0x9999999999999999999999999999999999999999",
        "PING",
        {}
    )

    assert result["success"] is False


def test_create_message_invalid_type(
    communication,
    peer_ids
):

    result = communication.create_message(
        peer_ids[0],
        peer_ids[1],
        "INVALID",
        {}
    )

    assert result["success"] is False


def test_create_message_invalid_payload(
    communication,
    peer_ids
):

    result = communication.create_message(
        peer_ids[0],
        peer_ids[1],
        "PING",
        "invalid"
    )

    assert result["success"] is False


def test_create_message_oversized_payload(
    communication,
    peer_ids
):

    result = communication.create_message(
        peer_ids[0],
        peer_ids[1],
        "PING",
        {"data": "A" * communication.MAX_MESSAGE_SIZE}
    )

    assert result["success"] is False


def test_create_message_non_serializable_payload(
    communication,
    peer_ids
):

    result = communication.create_message(
        peer_ids[0],
        peer_ids[1],
        "PING",
        {"data": object()}
    )

    assert result["success"] is False


# --------------------------------------------------
# MESSAGE VALIDATION
# --------------------------------------------------

def test_validate_valid_message(
    communication,
    valid_message
):

    assert communication.validate_message(valid_message)


def test_validate_non_dictionary_message(communication):

    assert not communication.validate_message("invalid")


def test_validate_missing_field(
    communication,
    valid_message
):

    message = dict(valid_message)
    message.pop("payload")

    assert not communication.validate_message(message)


def test_validate_extra_field(
    communication,
    valid_message
):

    message = dict(valid_message)
    message["extra"] = True

    assert not communication.validate_message(message)


def test_validate_invalid_message_id(
    communication,
    valid_message
):

    message = dict(valid_message)
    message["message_id"] = "invalid"

    assert not communication.validate_message(message)


def test_validate_unauthorized_sender(
    communication,
    valid_message
):

    message = dict(valid_message)

    message["sender_id"] = (
        "0x9999999999999999999999999999999999999999"
    )

    assert not communication.validate_message(message)


def test_validate_unauthorized_receiver(
    communication,
    valid_message
):

    message = dict(valid_message)

    message["receiver_id"] = (
        "0x9999999999999999999999999999999999999999"
    )

    assert not communication.validate_message(message)


def test_validate_invalid_message_type(
    communication,
    valid_message
):

    message = dict(valid_message)
    message["message_type"] = "INVALID"

    assert not communication.validate_message(message)


def test_validate_invalid_payload(
    communication,
    valid_message
):

    message = dict(valid_message)
    message["payload"] = "invalid"

    assert not communication.validate_message(message)


def test_validate_old_timestamp(
    communication,
    valid_message
):

    message = dict(valid_message)

    message["timestamp"] = (
        time.time() - communication.MAX_TIMESTAMP_AGE - 10
    )

    assert not communication.validate_message(message)


def test_validate_future_timestamp(
    communication,
    valid_message
):

    message = dict(valid_message)

    message["timestamp"] = (
        time.time() + communication.MAX_FUTURE_OFFSET + 10
    )

    assert not communication.validate_message(message)


def test_validate_boolean_timestamp(
    communication,
    valid_message
):

    message = dict(valid_message)
    message["timestamp"] = True

    assert not communication.validate_message(message)


def test_validate_non_numeric_timestamp(
    communication,
    valid_message
):

    message = dict(valid_message)
    message["timestamp"] = "invalid"

    assert not communication.validate_message(message)


def test_validate_oversized_message(
    communication,
    valid_message
):

    message = dict(valid_message)

    message["payload"] = {
        "data": "A" * communication.MAX_MESSAGE_SIZE
    }

    assert not communication.validate_message(message)


# --------------------------------------------------
# MESSAGE HANDLERS
# --------------------------------------------------

def test_register_valid_handler(communication):

    handler = lambda payload: payload

    assert communication.register_handler(
        "PING",
        handler
    )


def test_register_invalid_handler_type(communication):

    assert not communication.register_handler(
        "INVALID",
        lambda payload: payload
    )


def test_register_non_callable_handler(communication):

    assert not communication.register_handler(
        "PING",
        "invalid"
    )


# --------------------------------------------------
# MESSAGE RECEIVING
# --------------------------------------------------

def test_receive_valid_message(
    communication,
    valid_message,
    peer_ids
):

    communication.register_handler(
        "PING",
        lambda payload: "PONG"
    )

    result = communication.receive_message(
        valid_message,
        peer_ids[1]
    )

    assert result["success"] is True
    assert result["result"] == "PONG"


def test_receive_invalid_message(
    communication,
    peer_ids
):

    result = communication.receive_message(
        {},
        peer_ids[1]
    )

    assert result["success"] is False


def test_receive_wrong_receiver(
    communication,
    valid_message,
    peer_ids
):

    result = communication.receive_message(
        valid_message,
        peer_ids[0]
    )

    assert result["success"] is False
    assert result["error"] == "Receiver mismatch"


def test_receive_duplicate_message(
    communication,
    valid_message,
    peer_ids
):

    communication.register_handler(
        "PING",
        lambda payload: "PONG"
    )

    first = communication.receive_message(
        valid_message,
        peer_ids[1]
    )

    second = communication.receive_message(
        valid_message,
        peer_ids[1]
    )

    assert first["success"] is True
    assert second["success"] is False
    assert second["error"] == "Duplicate message"


def test_receive_without_handler(
    communication,
    valid_message,
    peer_ids
):

    result = communication.receive_message(
        valid_message,
        peer_ids[1]
    )

    assert result["success"] is False
    assert result["error"] == "Message handler not found"


def test_receive_handler_exception(
    communication,
    valid_message,
    peer_ids
):

    def failing_handler(payload):
        raise RuntimeError("Test error")

    communication.register_handler(
        "PING",
        failing_handler
    )

    result = communication.receive_message(
        valid_message,
        peer_ids[1]
    )

    assert result["success"] is False
    assert result["error"] == "Message processing failed"


# --------------------------------------------------
# SECURITY EVENTS
# --------------------------------------------------

def test_invalid_message_generates_event(
    communication,
    peer_ids
):

    communication.receive_message(
        {},
        peer_ids[1]
    )

    events = communication.get_security_events()

    assert any(
        event["event_type"] == "INVALID_NETWORK_MESSAGE"
        for event in events
    )


def test_replay_generates_event(
    communication,
    valid_message,
    peer_ids
):

    communication.register_handler(
        "PING",
        lambda payload: "PONG"
    )

    communication.receive_message(
        valid_message,
        peer_ids[1]
    )

    communication.receive_message(
        valid_message,
        peer_ids[1]
    )

    events = communication.get_security_events()

    assert any(
        event["event_type"] == "MESSAGE_REPLAY_ATTEMPT"
        for event in events
    )


def test_handler_error_generates_event(
    communication,
    valid_message,
    peer_ids
):

    def failing_handler(payload):
        raise RuntimeError("Test error")

    communication.register_handler(
        "PING",
        failing_handler
    )

    communication.receive_message(
        valid_message,
        peer_ids[1]
    )

    events = communication.get_security_events()

    assert any(
        event["event_type"] == "MESSAGE_HANDLER_ERROR"
        for event in events
    )


def test_get_security_events_returns_copy(communication):

    events = communication.get_security_events()

    events.append({
        "event_type": "FAKE"
    })

    assert communication.get_security_events() == []


# --------------------------------------------------
# SQLITE INTEGRATION
# --------------------------------------------------

def test_communication_with_persistent_network(tmp_path):

    database_path = tmp_path / "communication.db"

    storage = VOINStorageEngine(
        db_path=str(database_path)
    )

    network = VOINNetworkSecurityEngine(
        storage_engine=storage
    )

    network.register_peer(
        "0x1234567890abcdef1234567890abcdef12345678",
        "http://127.0.0.1:8001"
    )

    network.register_peer(
        "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        "http://127.0.0.1:8002"
    )

    communication = VOINCommunicationEngine(
        network_engine=network
    )

    result = communication.create_message(
        "0x1234567890abcdef1234567890abcdef12345678",
        "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        "PING",
        {"status": "active"}
    )

    assert result["success"] is True
