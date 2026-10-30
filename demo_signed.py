from signatures import keygen, address, sign_transaction
from signed_chain import SignedVoinChain

pk, sk = keygen()
sender = address(pk)
ledger = SignedVoinChain({sender: 1000}, difficulty=2)
ledger.register_validator("demo_validator", 50)

tx = {
    "sender": sender, "recipient": "bob",
    "amount": 250, "nonce": 1
}
item = {
    "transaction": tx,
    "public_key": pk.hex(),
    "signature": sign_transaction(tx, pk, sk).hex()
}
ledger.add_block([item], "demo_validator")

print("Demo transaksi bertanda tangan ML-DSA-44")
print("Saldo pengirim:", ledger.balances()[sender])
print("Saldo Bob:", ledger.balances()["bob"])
print("Integritas rantai:", ledger.validate())
print("Eksperimen lokal, bukan untuk dana nyata.")
