"""
VOIN TRANSACTION SECURITY TEST V1.0

Tests transaction validation and integrity.
"""

from security.transaction import VOINTransactionSecurity


def setup_engine():

    return VOINTransactionSecurity()


def test_valid_transaction():

    engine = setup_engine()

    result = engine.create_transaction_record(
        sender="0x1111111111111111111111111111111111111111",
        receiver="0x2222222222222222222222222222222222222222",
        amount="100",
        asset="VOIN",
        network="VOIN"
    )

    assert result["success"] is True
    assert result["status"] == "TRANSACTION_CREATED"


def test_invalid_sender():

    engine = setup_engine()

    result = engine.create_transaction_record(
        sender="INVALID",
        receiver="0x2222222222222222222222222222222222222222",
        amount="100"
    )

    assert result["success"] is False
    assert result["status"] == "INVALID_SENDER"


def test_invalid_receiver():

    engine = setup_engine()

    result = engine.create_transaction_record(
        sender="0x1111111111111111111111111111111111111111",
        receiver="INVALID",
        amount="100"
    )

    assert result["success"] is False
    assert result["status"] == "INVALID_RECEIVER"


def test_invalid_amount():

    engine = setup_engine()

    result = engine.create_transaction_record(
        sender="0x1111111111111111111111111111111111111111",
        receiver="0x2222222222222222222222222222222222222222",
        amount="-100"
    )

    assert result["success"] is False
    assert result["status"] == "INVALID_AMOUNT"


def test_transaction_integrity():

    engine = setup_engine()

    result = engine.create_transaction_record(
        sender="0x1111111111111111111111111111111111111111",
        receiver="0x2222222222222222222222222222222222222222",
        amount="250"
    )

    transaction_id = result["transaction"]["transaction_id"]

    assert engine.verify_integrity(transaction_id) is True


def test_transaction_tampering():

    engine = setup_engine()

    result = engine.create_transaction_record(
        sender="0x1111111111111111111111111111111111111111",
        receiver="0x2222222222222222222222222222222222222222",
        amount="250"
    )

    transaction_id = result["transaction"]["transaction_id"]

    engine.transactions[transaction_id]["data"]["amount"] = "999999"

    assert engine.verify_integrity(transaction_id) is False


def test_transaction_not_found():

    engine = setup_engine()

    assert engine.verify_integrity("UNKNOWN_ID") is False
