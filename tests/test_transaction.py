""" VOIN TRANSACTION SECURITY TEST V1.1
Tests transaction validation, integrity, idempotency protection and status management.
Development test module - not a production blockchain. """
from security.transaction import VOINTransactionSecurity
SENDER = "0x1111111111111111111111111111111111111111" RECEIVER = "0x2222222222222222222222222222222222222222"
def setup_engine(): return VOINTransactionSecurity()
def create_valid_transaction(engine, **kwargs): params = { "sender": SENDER, "receiver": RECEIVER, "amount": "100", "asset": "VOIN", "network": "VOIN" }
params.update(kwargs)

return engine.create_transaction_record(**params)
==========================================
BASIC TRANSACTION VALIDATION
==========================================
def test_valid_transaction(): engine = setup_engine()
result = create_valid_transaction(engine)

assert result["success"] is True
assert result["status"] == "TRANSACTION_CREATED"
def test_invalid_sender(): engine = setup_engine()
result = create_valid_transaction(
    engine,
    sender="INVALID"
)

assert result["success"] is False
assert result["status"] == "INVALID_SENDER"
def test_invalid_receiver(): engine = setup_engine()
result = create_valid_transaction(
    engine,
    receiver="INVALID"
)

assert result["success"] is False
assert result["status"] == "INVALID_RECEIVER"
def test_self_transfer_rejected(): engine = setup_engine()
result = create_valid_transaction(
    engine,
    receiver=SENDER
)

assert result["success"] is False
assert result["status"] == "SELF_TRANSFER_NOT_ALLOWED"
def test_invalid_amount(): engine = setup_engine()
invalid_amounts = [
    "-100",
    "0",
    "invalid",
    "NaN",
    "Infinity"
]

for amount in invalid_amounts:
    result = create_valid_transaction(
        engine,
        amount=amount
    )

    assert result["success"] is False
    assert result["status"] == "INVALID_AMOUNT"
def test_invalid_asset(): engine = setup_engine()
result = create_valid_transaction(
    engine,
    asset=""
)

assert result["success"] is False
assert result["status"] == "INVALID_ASSET"
def test_invalid_network(): engine = setup_engine()
result = create_valid_transaction(
    engine,
    network=""
)

assert result["success"] is False
assert result["status"] == "INVALID_NETWORK"
==========================================
IDEMPOTENCY PROTECTION
==========================================
def test_idempotency_key_creation(): engine = setup_engine()
result = create_valid_transaction(
    engine,
    idempotency_key="request-001"
)

assert result["success"] is True
assert result["transaction"]["status"] == "PENDING"
def test_duplicate_idempotency_key_rejected(): engine = setup_engine()
first = create_valid_transaction(
    engine,
    idempotency_key="request-002"
)

second = create_valid_transaction(
    engine,
    idempotency_key="request-002"
)

assert first["success"] is True
assert second["success"] is False

assert second["status"] == "DUPLICATE_TRANSACTION"

assert (
    second["original_transaction_id"]
    == first["transaction"]["transaction_id"]
)
def test_idempotency_key_conflict_rejected(): engine = setup_engine()
first = create_valid_transaction(
    engine,
    amount="100",
    idempotency_key="request-003"
)

second = create_valid_transaction(
    engine,
    amount="200",
    idempotency_key="request-003"
)

assert first["success"] is True
assert second["success"] is False

assert second["status"] == "IDEMPOTENCY_KEY_CONFLICT"
def test_same_idempotency_key_different_sender(): engine = setup_engine()
first = create_valid_transaction(
    engine,
    idempotency_key="request-004"
)

second = create_valid_transaction(
    engine,
    sender="0x3333333333333333333333333333333333333333",
    idempotency_key="request-004"
)

assert first["success"] is True
assert second["success"] is True
def test_invalid_idempotency_key(): engine = setup_engine()
invalid_keys = [
    "",
    "   ",
    "x" * 129
]

for key in invalid_keys:
    result = create_valid_transaction(
        engine,
        idempotency_key=key
    )

    assert result["success"] is False
    assert result["status"] == "INVALID_IDEMPOTENCY_KEY"
==========================================
TRANSACTION INTEGRITY
==========================================
def test_transaction_integrity(): engine = setup_engine()
result = create_valid_transaction(engine)

transaction_id = result["transaction"]["transaction_id"]

assert engine.verify_integrity(transaction_id) is True
def test_transaction_tampering(): engine = setup_engine()
result = create_valid_transaction(engine)

transaction_id = result["transaction"]["transaction_id"]

engine.transactions[transaction_id]["data"]["amount"] = "999999"

assert engine.verify_integrity(transaction_id) is False
def test_transaction_not_found(): engine = setup_engine()
assert engine.verify_integrity("UNKNOWN_ID") is False
==========================================
TRANSACTION STATUS MANAGEMENT
==========================================
def test_initial_transaction_status(): engine = setup_engine()
result = create_valid_transaction(engine)

transaction_id = result["transaction"]["transaction_id"]

transaction = engine.get_transaction(transaction_id)

assert transaction["status"] == "PENDING"
def test_pending_to_verified(): engine = setup_engine()
result = create_valid_transaction(engine)

transaction_id = result["transaction"]["transaction_id"]

assert engine.update_transaction_status(
    transaction_id,
    "VERIFIED"
) is True

transaction = engine.get_transaction(transaction_id)

assert transaction["status"] == "VERIFIED"
def test_pending_to_rejected(): engine = setup_engine()
result = create_valid_transaction(engine)

transaction_id = result["transaction"]["transaction_id"]

assert engine.update_transaction_status(
    transaction_id,
    "REJECTED"
) is True

transaction = engine.get_transaction(transaction_id)

assert transaction["status"] == "REJECTED"
def test_verified_transaction_cannot_change_status(): engine = setup_engine()
result = create_valid_transaction(engine)

transaction_id = result["transaction"]["transaction_id"]

assert engine.update_transaction_status(
    transaction_id,
    "VERIFIED"
) is True

assert engine.update_transaction_status(
    transaction_id,
    "REJECTED"
) is False
def test_rejected_transaction_cannot_change_status(): engine = setup_engine()
result = create_valid_transaction(engine)

transaction_id = result["transaction"]["transaction_id"]

assert engine.update_transaction_status(
    transaction_id,
    "REJECTED"
) is True

assert engine.update_transaction_status(
    transaction_id,
    "VERIFIED"
) is False
def test_invalid_status_rejected(): engine = setup_engine()
result = create_valid_transaction(engine)

transaction_id = result["transaction"]["transaction_id"]

assert engine.update_transaction_status(
    transaction_id,
    "UNKNOWN"
) is False
def test_status_update_preserves_integrity(): engine = setup_engine()
result = create_valid_transaction(engine)

transaction_id = result["transaction"]["transaction_id"]

assert engine.update_transaction_status(
    transaction_id,
    "VERIFIED"
) is True

assert engine.verify_integrity(transaction_id) is True
def test_status_update_rejected_after_tampering(): engine = setup_engine()
result = create_valid_transaction(engine)

transaction_id = result["transaction"]["transaction_id"]

engine.transactions[transaction_id]["data"]["amount"] = "999999"

assert engine.update_transaction_status(
    transaction_id,
    "VERIFIED"
) is False
def test_unknown_transaction_status_update(): engine = setup_engine()
assert engine.update_transaction_status(
    "UNKNOWN_ID",
    "VERIFIED"
) is False
==========================================
ENGINE INFORMATION
==========================================
def test_engine_info(): info = VOINTransactionSecurity.engine_info()
assert info["version"] == "1.1.0"
assert info["idempotency_protection"] is True
assert info["integrity_verification"] is True
assert info["transaction_status_management"] is True
