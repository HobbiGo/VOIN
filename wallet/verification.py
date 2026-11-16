import time
import secrets
import json
from eth_account import Account
from eth_account.messages import encode_defunct

# Import untuk fitur Multi-chain
from web3 import Web3
from solana.rpc.api import Client
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.system_program import transfer, TransferParams
from solders.transaction import Transaction

# Import ML-DSA
from security.pqc_signer import verify as pqc_verify, sign as pqc_sign, generate_keypair as pqc_keygen

class VOINWalletVerification:
    """Fitur Lama: Challenge-Response untuk membuktikan kepemilikan wallet."""
    VERSION = "1.0"
    CHALLENGE_EXPIRY = 300

    def __init__(self):
        self.challenges = {}

    def create_challenge(self, wallet_address):
        if not isinstance(wallet_address, str):
            raise TypeError("Wallet address must be a string")
        if not Account.is_address(wallet_address):
            raise ValueError("Invalid wallet address")

        checksum_address = Account.to_checksum_address(wallet_address)
        nonce = secrets.token_hex(32)
        timestamp = int(time.time())

        message = (
            "VOIN Wallet Verification\n"
            "Platform: VOIN\n"
            f"Wallet: {checksum_address}\n"
            f"Nonce: {nonce}\n"
            f"Timestamp: {timestamp}\n"
            "Purpose: Verify wallet ownership"
        )
        self.challenges[checksum_address.lower()] = {
            "message": message,
            "created_at": time.time()
        }
        return message

    def verify_signature(self, wallet_address, signature):
        if not isinstance(wallet_address, str) or not Account.is_address(wallet_address):
            return False
        if not isinstance(signature, str):
            return False

        key = wallet_address.lower()
        challenge = self.challenges.get(key)

        if challenge is None:
            return False
        if time.time() - challenge["created_at"] > self.CHALLENGE_EXPIRY:
            del self.challenges[key]
            return False

        try:
            signable_message = encode_defunct(text=challenge["message"])
            recovered_address = Account.recover_message(signable_message, signature=signature)
            if recovered_address.lower() != key:
                return False
            del self.challenges[key]
            return True
        except (ValueError, TypeError):
            return False


class VOINMultiChainWallet:
    """
    Menangani pengiriman ETH/BNB/SOL dan penandatanganan transaksi L1 VOIN.
    """
    EVM_CONFIG = {
        "ethereum": {"rpc": "https://cloudflare-eth.com", "chain_id": 1}, 
        "bnb": {"rpc": "https://bsc-dataseed.binance.org", "chain_id": 56}
    }

    @staticmethod
    def send_evm(chain, private_key, to_address, amount_ether):
        """Kirim ETH atau BNB."""
        if chain not in VOINMultiChainWallet.EVM_CONFIG:
            raise ValueError("Chain not supported. Use 'ethereum' or 'bnb'.")
            
        cfg = VOINMultiChainWallet.EVM_CONFIG[chain]
        w3 = Web3(Web3.HTTPProvider(cfg["rpc"]))
        acct = w3.eth.account.from_key(private_key)
        
        tx = {
            "to": to_address,
            "value": w3.to_wei(amount_ether, "ether"),
            "gas": 21000,
            "gasPrice": w3.eth.gas_price,
            "nonce": w3.eth.get_transaction_count(acct.address),
            "chainId": cfg["chain_id"],
        }
        signed = acct.sign_transaction(tx)
        return w3.eth.send_raw_transaction(signed.raw_transaction).hex()

    @staticmethod
    def send_solana(private_key_bytes, to_address, amount_sol):
        """Kirim SOL."""
        client = Client("https://api.mainnet-beta.solana.com")
        sender = Keypair.from_bytes(private_key_bytes)
        
        lamports = int(amount_sol * 1_000_000_000)
        txn = Transaction().add(
            transfer(TransferParams(
                from_pubkey=sender.pubkey(),
                to_pubkey=Pubkey.from_string(to_address),
                lamports=lamports
            ))
        )
        response = client.send_transaction(txn, sender)
        return str(response.value)

    @staticmethod
    def sign_voin_transaction(tx_data, evm_private_key, pqc_private_key):
        """
        Menandatangani transaksi untuk ledger L1 VOIN (Hybrid Signature).
        """
        payload = {k: tx_data[k] for k in ("sender", "recipient", "amount", "nonce")}
        message = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

        # 1. Tanda tangan ECDSA
        acct = Account.from_key(evm_private_key)
        signable = encode_defunct(primitive=message)
        signed_evm = acct.sign_message(signable)
        sig_ecdsa = signed_evm.signature.hex()

        # 2. Tanda tangan ML-DSA
        sig_mldsa_bytes = pqc_sign(message, pqc_private_key)
        sig_mldsa_hex = sig_mldsa_bytes.hex()

        return sig_ecdsa, sig_mldsa_hex

# Fungsi Helper untuk voin.py
def verify_hybrid_tx(message: bytes, sig_ecdsa: str, sig_mldsa_hex: str, expected_address: str, pk_mldsa_hex: str = None) -> bool:
    """Fungsi verifikasi gabungan untuk ledger."""
    # Verifikasi ECDSA
    try:
        signable = encode_defunct(primitive=message)
        recovered = Account.recover_message(signable, signature=sig_ecdsa)
        if recovered.lower() != expected_address.lower():
            return False
    except Exception:
        return False

    # Verifikasi ML-DSA
    if pk_mldsa_hex:
        if not pqc_verify(message, bytes.fromhex(sig_mldsa_hex), bytes.fromhex(pk_mldsa_hex)):
            return False
            
    return True
