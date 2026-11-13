import time
import secrets
from eth_account import Account
from eth_account.messages import encode_defunct

class VOINWalletVerification:

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

        if not isinstance(wallet_address, str):
            return False

        if not Account.is_address(wallet_address):
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
            signable_message = encode_defunct(
                text=challenge["message"]
            )

            recovered_address = Account.recover_message(
                signable_message,
                signature=signature
            )

            if recovered_address.lower() != key:
                return False

            del self.challenges[key]

            return True

        except (ValueError, TypeError):
            return False

    def clear_expired_challenges(self):

        current_time = time.time()

        expired_addresses = []

        for address, challenge in self.challenges.items():

            if current_time - challenge["created_at"] > self.CHALLENGE_EXPIRY:
                expired_addresses.append(address)

        for address in expired_addresses:
            del self.challenges[address]

        return len(expired_addresses)


if __name__ == "__main__":
    verifier = VOINWalletVerification()

    print("VOIN WALLET VERIFICATION ENGINE")
    print("Version:", verifier.VERSION)
    print("Status: INITIALIZED")
    print("Challenge Expiry:", verifier.CHALLENGE_EXPIRY)
