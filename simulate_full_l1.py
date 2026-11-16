import subprocess
import time
import requests
import sys
from eth_account import Account
from eth_account.messages import encode_defunct
from security.pqc_signer import generate_keypair, sign as pqc_sign
from voin import canonical_tx_message, canonical_block_message

NODE_A_PORT = 5000
NODE_B_PORT = 5001

def wait_for_node(url, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        try:
            if requests.get(f"{url}/info", timeout=1).status_code == 200:
                return True
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(0.5)
    return False

def main():
    print("=== MEMULAI SIMULASI L1 PENUH (P2P + API + WALLET) ===")
    
    # Nyalakan Node
    proc_a = subprocess.Popen([sys.executable, "node.py", str(NODE_A_PORT)])
    proc_b = subprocess.Popen([sys.executable, "node.py", str(NODE_B_PORT)])
    
    if not wait_for_node(f"http://127.0.0.1:{NODE_A_PORT}") or not wait_for_node(f"http://127.0.0.1:{NODE_B_PORT}"):
        print("Gagal menyalakan node.")
        proc_a.terminate(); proc_b.terminate(); return

    try:
        # Hubungkan Peer
        requests.post(f"http://127.0.0.1:{NODE_A_PORT}/peers/register", json={"peer_address": f"http://127.0.0.1:{NODE_B_PORT}"})
        requests.post(f"http://127.0.0.1:{NODE_B_PORT}/peers/register", json={"peer_address": f"http://127.0.0.1:{NODE_A_PORT}"})
        time.sleep(1)

        # 1. Buat Akun & Daftarkan ke Genesis Node A (Asumsi Alice ada di genesis)
        alice = Account.create()
        alice_pk, alice_sk = generate_keypair()
        
        # Validator
        val = Account.create()
        val_pk, val_sk = generate_keypair()

        # Karena Genesis sudah diinisialisasi dengan "alice" dummy, kita harus membuat state store manual atau
        # mengirim dari alice asli. Untuk simulasi ini, kita akan override saldo Alice di memori Node A.
        # (Dalam produksi, ini adalah hasil dari genesis block).
        
        # SUNTIK SALDO (Hanya untuk simulasi, karena Genesis Node A dibuat dengan dummy "alice")
        # Ini akan kita lewati dengan membuat transaksi dari "alice" ke alamat asli alice_acct.
        # TAPI, karena kita ingin menguji API /transaction, kita kirim langsung dari alice_acct.
        
        # Karena kita tidak bisa akses memori node.py dari sini, kita harus mendaftarkan saldo Alice via transaksi genesis.
        # Solusi: Node A dan B dibuat dengan DB baru. Kita akan menambal DB Node A via API.
        # (Untuk saat ini, kita asumsikan Node A memiliki saldo untuk alice_acct)
        
        print("Menyiapkan data transaksi (Alice -> Bob)...")
        
        # 2. Buat Transaksi
        tx = {"sender": alice.address, "recipient": "0xBobAddress", "amount": 100, "nonce": 1}
        msg = canonical_tx_message(tx)
        tx["sig_ecdsa"] = alice.sign_message(encode_defunct(primitive=msg)).signature.hex()
        tx["sig_mldsa"] = pqc_sign(msg, alice_sk).hex()

        # 3. Buat Block (Simulasi Node Validator membuat block)
        # Karena API node kita butuh validator_sig, wallet harus membuatnya (simulasi)
        # Di sini kita membuat block kosong dulu untuk mendapatkan hash dan index
        temp_chain = VoinChain(allocations={alice.address: 1000}, difficulty=1, store=StateStore(":memory:"))
        temp_chain.register_validator(val.address, 50, val.address, val_pk.hex())
        
        block = temp_chain.prepare_block([tx], val.address)
        block_msg = canonical_block_message(block)
        v_sig_e = val.sign_message(encode_defunct(primitive=block_msg)).signature.hex()
        v_sig_p = pqc_sign(block_msg, val_sk).hex()

        # 4. Kirim ke Node A
        print("Mengirim transaksi ke Node A via API...")
        payload = {
            "tx": tx, "sig_ecdsa": tx["sig_ecdsa"], "sig_mldsa": tx["sig_mldsa"],
            "validator_id": val.address, "validator_sig_ecdsa": v_sig_e, "validator_sig_mldsa": v_sig_p
        }
        res = requests.post(f"http://127.0.0.1:{NODE_A_PORT}/transaction", json=payload)
        print(f"Respons Node A: {res.json()}")
        
        time.sleep(1)
        
        # 5. Cek Saldo di Node B (P2P Sinkronisasi)
        print("Mengecek saldo di Node B (P2P)...")
        res_balance = requests.get(f"http://127.0.0.1:{NODE_B_PORT}/balance/{alice.address}")
        print(f"Saldo di Node B: {res_balance.json()}")

    finally:
        print("Mematikan node...")
        proc_a.terminate(); proc_b.terminate(); proc_a.wait(); proc_b.wait()

if __name__ == "__main__":
    main()
