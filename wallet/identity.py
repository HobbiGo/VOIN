import uuid
import time
import secrets
import hashlib
import json
import re

class VOINIdentity:

    VERSION = "1.0"

    def __init__(self):
        self.identity = None

    @staticmethod
    def generate_identity_id():
        unique_data = (
            str(uuid.uuid4()) +
            str(time.time_ns()) +
            secrets.token_hex(16)
        )
        return hashlib.sha256(unique_data.encode("utf-8")).hexdigest()

    @staticmethod
    def validate_wallet_address(wallet_address):
        if not isinstance(wallet_address, str):
            raise TypeError("Wallet address must be a string")
        if not re.fullmatch(r"0x[a-fA-F0-9]{40}", wallet_address):
            raise ValueError("Invalid wallet address format")
        return True

    def create_identity(self, wallet_address, network="BSC"):
        self.validate_wallet_address(wallet_address)

        if not isinstance(network, str) or not network.strip():
            raise ValueError("Network is required")

        identity_id = self.generate_identity_id()

        self.identity = {
            "platform": "VOIN",
            "engine": "Wallet Identity Engine",
            "version": self.VERSION,
            "identity_id": identity_id,
            "wallet_address": wallet_address,
            "network": network.upper(),
            "created_at": int(time.time()),
            "status": "ACTIVE"
        }

        return self.identity.copy()

    def verify_identity(self, identity_id):
        if not self.identity:
            return False
        return (
            self.identity["identity_id"] == identity_id and
            self.identity["status"] == "ACTIVE"
        )

    def export_identity(self):
        if not self.identity:
            return None
        return json.dumps(self.identity, indent=4)

    def deactivate_identity(self):
        if not self.identity:
            return False
        self.identity["status"] = "INACTIVE"
        return True


if __name__ == "__main__":
    voin = VOINIdentity()

    identity = voin.create_identity(
        wallet_address="0x0000000000000000000000000000000000000000",
        network="BSC"
    )

    print("VOIN IDENTITY CREATED")
    print(json.dumps(identity, indent=4))

    print("\nIDENTITY VERIFICATION:")
    print(voin.verify_identity(identity["identity_id"]))

    print("\nIDENTITY EXPORT:")
    print(voin.export_identity())
