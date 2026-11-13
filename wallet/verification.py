VERSION = "1.0"
CHALLENGE_EXPIRY = 300

def __init__(self):
    self.challenges = {}

def create_challenge(self, wallet_address):

    if not isinstance(wallet_address, str):
        raise TypeError("Invalid wallet address")

    if not Account.is_address(wallet_address):
        raise ValueError("Invalid wallet address")

    nonce = secrets.token_hex(32)

    message = (
        "VOIN Wallet Verification\n"
        "Platform: VOIN\n"
        f"Wallet: {wallet_address}\n"
        f"Nonce: {nonce}\n"
        f"Timestamp: {int(time.time())}"
    )

    self.challenges[wallet_address.lower()] = {
        "message": message,
        "nonce": nonce,
        "created_at": time.time()
    }

    return message

def verify_signature(
    self,
    wallet_address,
    signature
):

    key = wallet_address.lower()

    challenge = self.challenges.get(key)

    if not challenge:
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

    except Exception:
        return False
