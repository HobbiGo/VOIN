from transactions_v2 import (
    crypto, address, sign_transaction, CHAIN_ID
)
from strict_chain import StrictVoinChain

alice_pk, alice_sk = crypto.keygen()
bob_pk, bob_sk = crypto.keygen()
alice, bob = address(alice_pk), address(bob_pk)

ledger = StrictVoinChain({alice: 1000}, difficulty=2)
ledger.register_validator("demo", 50)


def transfer(pk, sk, recipient, amount, nonce):
    tx = {
        "chain_id": CHAIN_ID,
        "sender": address(pk), "recipient": recipient,
        "amount": amount, "nonce": nonce
    }
    item = {
        "transaction": tx,
        "public_key": pk.hex(),
        "signature": sign_transaction(tx, pk, sk).hex()
    }
    ledger.add_block([item], "demo")


transfer(alice_pk, alice_sk, bob, 250, 1)
transfer(bob_pk, bob_sk, alice, 100, 1)

print("Jaringan:", CHAIN_ID)
print("Saldo Alice:", ledger.balances()[alice])
print("Saldo Bob:", ledger.balances()[bob])
print("Integritas rantai:", ledger.validate())
print("Demo lokal; bukan uang nyata.")

import tempfile
from pathlib import Path
from ledger_storage import save_ledger, load_ledger

with tempfile.TemporaryDirectory() as folder:
    path = Path(folder) / "ledger.json"
    save_ledger(ledger, path)
    restored = load_ledger(
        path, allocations={alice: 1000}, difficulty=2
    )
    assert restored.chain == ledger.chain
    assert restored.balances() == ledger.balances()
    print("Simpan dan muat ulang: berhasil")
    print("Saldo Alice dipulihkan:", restored.balances()[alice])
    print("Saldo Bob dipulihkan:", restored.balances()[bob])
    print("Integritas setelah dimuat:", restored.validate())
