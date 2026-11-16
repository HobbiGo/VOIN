import requests
import json
from eth_account import Account
from eth_account.messages import encode_defunct
from security.pqc_signer import generate_keypair, sign as pqc_sign
from voin import canonical_tx_message

NODE_URL = "http://127.0.0.1:5000"

# 1. Siapkan Akun
alice = Account.create()
alice_pk_pqc, alice_sk_pqc = generate_keypair()

# Daftarkan kunci ML-DSA Alice ke Node
requests.post(f"{NODE_URL}/register_key", json={
    "address": alice.address, "pk_ecdsa": alice.address, "pk_mldsa": alice_pk_pqc.hex()
})

def send_tx(recipient, amount, nonce, data_payload):
    tx = {
        "sender": alice.address, 
        "recipient": recipient, 
        "amount": amount, 
        "nonce": nonce, 
        "data": data_payload
    }
    msg = canonical_tx_message(tx)
    tx["sig_ecdsa"] = alice.sign_message(encode_defunct(primitive=msg)).signature.hex()
    tx["sig_mldsa"] = pqc_sign(msg, alice_sk_pqc).hex()
    
    # Kirim ke Node
    res = requests.post(f"{NODE_URL}/transaction", json=tx)
    print(f"Response: {res.json()}")

# ==========================================
# SKENARIO SMART CONTRACT
# ==========================================
CONTRACT_ADDRESS = "0xVOIN_Web4_Messenger_Contract"

print("1. Deploying Contract...")
send_tx(
    recipient=CONTRACT_ADDRESS, 
    amount=0, 
    nonce=1, 
    data_payload={"action": "deploy", "code": "contract Messenger { store message; }"}
)

print("\n2. Calling Contract (Menyimpan Pesan)...")
send_tx(
    recipient=CONTRACT_ADDRESS, 
    amount=0, 
    nonce=2, 
    data_payload={"action": "call", "payload": {"message": "Halo Dunia Web4 dari VOIN!"}}
)
