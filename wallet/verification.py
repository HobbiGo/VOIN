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

# Database sementara (in-memory) untuk menyimpan Public Key ML-DSA milik user
# Di produksi, ini harus disimpan di SQLite (StateStore)
ACCOUNT_KEYS = {}

def register_account_keys(address, pk_ecdsa, pk_mldsa_hex):
    """Mendaftarkan Public Key ML-DSA milik pengguna."""
    ACCOUNT_KEYS[address.lower()] = {
        "pk_ecdsa": pk_ecdsa,
        "pk_mldsa": pk_mldsa_hex
    }

def verify_hybrid_tx(message: bytes, sig_ecdsa: str, sig_mldsa_hex: str, expected_address: str, pk_mldsa_hex: str = None) -> bool:
    """Fungsi verifikasi gabungan untuk ledger."""
    # 1. Verifikasi ECDSA
    try:
        signable = encode_defunct(primitive=message)
        recovered = Account.recover_message(signable, signature=sig_ecdsa)
        if recovered.lower() != expected_address.lower():
            return False
    except Exception:
        return False

    # 2. Verifikasi ML-DSA
    # Jika pk_mldsa_hex tidak diberikan di argumen, cari di registry
    if not pk_mldsa_hex:
        user_data = ACCOUNT_KEYS.get(expected_address.lower())
        if not user_data:
            return False
        pk_mldsa_hex = user_data["pk_mldsa"]

    if not pqc_verify(message, bytes.fromhex(sig_mldsa_hex), bytes.fromhex(pk_mldsa_hex)):
        return False
        
    return True

# (Kelas VOINWalletVerification dan VOINMultiChainWallet biarkan seperti sebelumnya)
class VOINWalletVerification:
    VERSION = "1.0"
    CHALLENGE_EXPIRY = 300
    def __init__(self):
        self.challenges = {}
    def create_challenge(self, wallet_address):
        if not isinstance(wallet_address, str): raise TypeError("Wallet address must be a string")
        if not Account.is_address(wallet_address): raise ValueError("Invalid wallet address")
        checksum_address = Account.to_checksum_address(wallet_address)
        nonce = secrets.token_hex(32)
        timestamp = int(time.time())
        message = f"VOIN Wallet Verification\nPlatform: VOIN\nWallet: {checksum_address}\nNonce: {nonce}\nTimestamp: {timestamp}\nPurpose: Verify wallet ownership"
        self.challenges[checksum_address.lower()] = {"message": message, "created_at": time.time()}
        return message
    def verify_signature(self, wallet_address, signature):
        if not isinstance(wallet_address, str) or not Account.is_address(wallet_address): return False
        if not isinstance(signature, str): return False
        key = wallet_address.lower()
        challenge = self.challenges.get(key)
        if challenge is None: return False
        if time.time() - challenge["created_at"] > self.CHALLENGE_EXPIRY:
            del self.challenges[key]; return False
        try:
            signable_message = encode_defunct(text=challenge["message"])
            recovered_address = Account.recover_message(signable_message, signature=signature)
            if recovered_address.lower() != key: return False
            del self.challenges[key]; return True
        except (ValueError, TypeError): return False
