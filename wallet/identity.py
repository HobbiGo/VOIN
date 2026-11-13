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

    return hashlib.sha256(
        unique_data.encode()
    ).hexdigest()

def create_identity(self, wallet_address, network="BSC"):

    if not wallet_address:
        raise ValueError("Wallet address is required")

    if not isinstance(wallet_address, str):
        raise TypeError("Wallet address must be a string")

    identity_id = self.generate_identity_id()

    self.identity = {
        "platform": "VOIN",
        "engine": "Wallet Identity Engine",
        "version": self.VERSION,
        "identity_id": identity_id,
        "wallet_address": wallet_address,
        "network": network,
        "created_at": int(time.time()),
        "status": "ACTIVE"
    }

    return self.identity

def verify_identity(self, identity_id):

    if not self.identity:
        return False

    return (
        self.identity["identity_id"] == identity_id
        and self.identity["status"] == "ACTIVE"
    )

def export_identity(self):

    if not self.identity:
        return None

    return json.dumps(
        self.identity,
        indent=4
    )
voin = VOINIdentity()

identity = voin.create_identity(
    wallet_address="0x0000000000000000000000000000000000000000",
    network="BSC"
)

print("VOIN IDENTITY CREATED")
print(json.dumps(identity, indent=4))

# Contoh menggabungkan dua file identity:
# voin.merge_identity_files([
#     "identity_1.json",
#     "identity_2.json"
# ])
#
# print("IDENTITY FILES MERGED")
# print(voin.export_identity())
