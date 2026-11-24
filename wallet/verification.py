import time
import secrets
import json
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3
from solana.rpc.api import Client
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.system_program import transfer, TransferParams
from solders.transaction import Transaction
from security.pqc_signer import verify as pqc_verify, sign as pqc_sign

# Database sementara (in-memory) untuk menyimpan Public Key ML-DSA milik user.
# Untuk produksi/mainnet, hubungkan ke persistent storage (StateStore / SQLite / D1).
ACCOUNT_KEYS = {}


def register_account_keys(address: str, pk_ecdsa: str, pk_mldsa_hex: str):
    """Mendaftarkan Public Key ML-DSA milik pengguna."""
    if not isinstance(address, str) or not Account.is_address(address):
        raise ValueError("Invalid wallet address")
    if not isinstance(pk_mldsa_hex, str) or not pk_mldsa_hex.strip():
        raise ValueError("Invalid ML-DSA public key")

    ACCOUNT_KEYS[address.lower()] = {
        "pk_ecdsa": pk_ecdsa,
        "pk_mldsa": pk_mldsa_hex.strip(),
    }


def verify_hybrid_tx(
    message: bytes,
    sig_ecdsa: str,
    sig_mldsa_hex: str,
    expected_address: str,
    pk_mldsa_hex: str = None,
) -> bool:
    """Fungsi verifikasi gabungan (ECDSA + ML-DSA) untuk ledger."""
    if not isinstance(message, (bytes, bytearray)):
        return False
    if not isinstance(expected_address, str) or not Account.is_address(expected_address):
        return False
    if not isinstance(sig_ecdsa, str) or not isinstance(sig_mldsa_hex, str):
        return False

    normalized_address = expected_address.lower()

    # 1. Verifikasi ECDSA
    try:
        signable = encode_defunct(primitive=bytes(message))
        recovered = Account.recover_message(signable, signature=sig_ecdsa)
        if recovered.lower() != normalized_address:
            return False
    except Exception:
        return False

    # 2. Verifikasi ML-DSA
    resolved_pk_hex = pk_mldsa_hex
    if not resolved_pk_hex:
        user_data = ACCOUNT_KEYS.get(normalized_address)
        if not user_data:
            return False
        resolved_pk_hex = user_data.get("pk_mldsa")

    if not isinstance(resolved_pk_hex, str) or not resolved_pk_hex.strip():
        return False

    try:
        sig_mldsa_bytes = bytes.fromhex(sig_mldsa_hex.strip())
        pk_mldsa_bytes = bytes.fromhex(resolved_pk_hex.strip())
    except ValueError:
        return False

    try:
        return bool(pqc_verify(bytes(message), sig_mldsa_bytes, pk_mldsa_bytes))
    except Exception:
        return False


class VOINWalletVerification:
    VERSION = "1.0"
    CHALLENGE_EXPIRY = 300

    def __init__(self):
        self.challenges = {}

    def _cleanup_expired(self, now: float):
        expired_keys = [
            addr for addr, item in self.challenges.items()
            if now - item["created_at"] > self.CHALLENGE_EXPIRY
        ]
        for addr in expired_keys:
            del self.challenges[addr]

    def create_challenge(self, wallet_address: str) -> str:
        if not isinstance(wallet_address, str):
            raise TypeError("Wallet address must be a string")
        if not Account.is_address(wallet_address):
            raise ValueError("Invalid wallet address")

        now = time.time()
        self._cleanup_expired(now)

        checksum_address = Account.to_checksum_address(wallet_address)
        nonce = secrets.token_hex(32)
        timestamp = int(now)
        message = (
            f"VOIN Wallet Verification\n"
            f"Platform: VOIN\n"
            f"Wallet: {checksum_address}\n"
            f"Nonce: {nonce}\n"
            f"Timestamp: {timestamp}\n"
            f"Purpose: Verify wallet ownership"
        )
        self.challenges[checksum_address.lower()] = {
            "message": message,
            "created_at": now,
        }
        return message

    def verify_signature(self, wallet_address: str, signature: str) -> bool:
        if not isinstance(wallet_address, str) or not Account.is_address(wallet_address):
            return False
        if not isinstance(signature, str) or not signature.strip():
            return False

        now = time.time()
        self._cleanup_expired(now)

        key = wallet_address.lower()
        challenge = self.challenges.get(key)
        if challenge is None:
            return False

        if now - challenge["created_at"] > self.CHALLENGE_EXPIRY:
            del self.challenges[key]
            return False

        try:
            signable_message = encode_defunct(text=challenge["message"])
            recovered_address = Account.recover_message(signable_message, signature=signature.strip())
            if recovered_address.lower() != key:
                return False
            del self.challenges[key]
            return True
        except Exception:
            return False
