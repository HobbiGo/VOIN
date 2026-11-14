"""
VOIN VERIFICATION ENGINE TEST SUITE V1.1
Tests wallet authentication, challenge validation,
digital signatures, nonce protection, replay prevention
and thread-safe verification.
"""
import threading
import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from security.verification import VOINVerificationEngine
from security.nonce import VOINNonceEngine
@pytest.fixture
def wallet():
return Account.create()
@pytest.fixture
def verification_engine():
return VOINVerificationEngine(expiry_seconds=300)
def sign_message(wallet, message):
return Account.sign_message(
encode_defunct(text=message),
private_key=wallet.key
).signature.hex()
==========================================
CHALLENGE GENERATION
==========================================
def test_challenge_generation(verification_engine, wallet):
result = verification_engine.create_verification_challenge(
    wallet.address
)

assert result["success"] is True
assert "challenge_id" in result
assert "message" in result
assert "nonce" in result
assert "expires_at" in result

==========================================
WALLET SIGNATURE VERIFICATION
==========================================
def test_valid_wallet_signature(verification_engine, wallet):
challenge = verification_engine.create_verification_challenge(
    wallet.address
)

signature = sign_message(wallet, challenge["message"])

result = verification_engine.verify_wallet(
    challenge["challenge_id"],
    wallet.address,
    signature
)

assert result["success"] is True
assert result["status"] == "WALLET_VERIFIED"
assert result["version"] == "1.1.0"

def test_invalid_wallet(verification_engine):
result = verification_engine.create_verification_challenge(
    "INVALID_WALLET"
)

assert result["success"] is False
assert result["status"] == "INVALID_ADDRESS"

def test_invalid_signature(verification_engine, wallet):
challenge = verification_engine.create_verification_challenge(
    wallet.address
)

result = verification_engine.verify_wallet(
    challenge["challenge_id"],
    wallet.address,
    "invalid_signature"
)

assert result["success"] is False
assert result["status"] == "INVALID_SIGNATURE"

def test_signer_mismatch(verification_engine, wallet):
challenge = verification_engine.create_verification_challenge(
    wallet.address
)

other_wallet = Account.create()

signature = sign_message(
    other_wallet,
    challenge["message"]
)

result = verification_engine.verify_wallet(
    challenge["challenge_id"],
    wallet.address,
    signature
)

assert result["success"] is False
assert result["status"] == "SIGNER_MISMATCH"

==========================================
REPLAY PROTECTION
==========================================
def test_replay_protection(verification_engine, wallet):
challenge = verification_engine.create_verification_challenge(
    wallet.address
)

signature = sign_message(wallet, challenge["message"])

first_result = verification_engine.verify_wallet(
    challenge["challenge_id"],
    wallet.address,
    signature
)

second_result = verification_engine.verify_wallet(
    challenge["challenge_id"],
    wallet.address,
    signature
)

assert first_result["success"] is True
assert second_result["success"] is False
assert second_result["status"] == "CHALLENGE_ALREADY_USED"

==========================================
CHALLENGE EXPIRATION
==========================================
def test_challenge_expiration(verification_engine, wallet):
challenge = verification_engine.create_verification_challenge(
    wallet.address
)

verification_engine.challenge_engine.challenges[
    challenge["challenge_id"]
]["expires_at"] = 0

result = verification_engine.verify_wallet(
    challenge["challenge_id"],
    wallet.address,
    "invalid_signature"
)

assert result["success"] is False
assert result["status"] == "INVALID_OR_EXPIRED_CHALLENGE"

==========================================
INVALID CHALLENGE ID
==========================================
def test_invalid_challenge_id(verification_engine, wallet):
result = verification_engine.verify_wallet(
    "INVALID_ID",
    wallet.address,
    "invalid_signature"
)

assert result["success"] is False
assert result["status"] == "INVALID_OR_EXPIRED_CHALLENGE"

def test_unknown_challenge_id(verification_engine, wallet):
result = verification_engine.verify_wallet(
    "a" * 64,
    wallet.address,
    "invalid_signature"
)

assert result["success"] is False
assert result["status"] == "INVALID_OR_EXPIRED_CHALLENGE"

==========================================
NONCE REUSE PROTECTION
==========================================
def test_nonce_reuse_protection(wallet):
nonce_engine = VOINNonceEngine()

generated = nonce_engine.generate_nonce(
    wallet.address
)

first_check = nonce_engine.verify_nonce(
    wallet.address,
    generated["nonce"]
)

second_check = nonce_engine.verify_nonce(
    wallet.address,
    generated["nonce"]
)

assert first_check is True
assert second_check is False

==========================================
THREAD-SAFE VERIFICATION
==========================================
def test_concurrent_challenge_verification(
verification_engine,
wallet
):
challenge = verification_engine.create_verification_challenge(
    wallet.address
)

signature = sign_message(wallet, challenge["message"])

results = []
results_lock = threading.Lock()

def verify():

    result = verification_engine.verify_wallet(
        challenge["challenge_id"],
        wallet.address,
        signature
    )

    with results_lock:
        results.append(result)

threads = [
    threading.Thread(target=verify)
    for _ in range(5)
]

for thread in threads:
    thread.start()

for thread in threads:
    thread.join()

successful = [
    result for result in results
    if result["success"] is True
]

assert len(successful) == 1
assert len(results) == 5

==========================================
ENGINE INFORMATION
==========================================
def test_verification_engine_info():
info = VOINVerificationEngine.engine_info()

assert info["engine"] == "VOIN Verification Engine"
assert info["version"] == "1.1.0"
assert info["status"] == "READY_FOR_TESTING"
assert info["challenge_verification"] is True
assert info["signature_verification"] is True
assert info["replay_protection"] is True
assert info["atomic_verification"] is True
assert info["thread_safety"] is True

