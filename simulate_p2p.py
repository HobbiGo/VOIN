import subprocess
import time
import requests
import json
import os
import sys

# Konfigurasi
NODE_A_PORT = 5000
NODE_B_PORT = 5001
NODE_A_URL = f"http://127.0.0.1:{NODE_A_PORT}"
NODE_B_URL = f"http://127.0.0.1:{NODE_B_PORT}"

def wait_for_node(url, timeout=10):
    """Menunggu node menyala."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            response = requests.get(f"{url}/info", timeout=1)
            if response.status_code == 200:
                return True
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(0.5)
    return False

def main():
    print("=== MEMULAI SIMULASI JARINGAN P2P VOIN ===")

    # 1. Nyalakan Node A dan Node B di background
    print(f"Menyalakan Node A (Port {NODE_A_PORT})...")
    proc_a = subprocess.Popen([sys.executable, "node.py", str(NODE_A_PORT)])
    
    print(f"Menyalakan Node B (Port {NODE_B_PORT})...")
    proc_b = subprocess.Popen([sys.executable, "node.py", str(NODE_B_PORT)])

    # Tunggu sampai keduanya siap
    if not wait_for_node(NODE_A_URL) or not wait_for_node(NODE_B_URL):
        print("Gagal menyalakan node. Pastikan port tidak dipakai.")
        proc_a.terminate()
        proc_b.terminate()
        return

    try:
        # 2. Hubungkan Node B ke Node A (Saling mendaftar)
        print("\nMenghubungkan Node A dan Node B...")
        requests.post(f"{NODE_A_URL}/peers/register", json={"peer_address": NODE_B_URL})
        requests.post(f"{NODE_B_URL}/peers/register", json={"peer_address": NODE_A_URL})
        time.sleep(1)

        # Cek status awal
        info_a = requests.get(f"{NODE_A_URL}/info").json()
        info_b = requests.get(f"{NODE_B_URL}/info").json()
        print(f"Tinggi Blok Awal - Node A: {info_a['height']}, Node B: {info_b['height']}")

        # 3. Siapkan Data Transaksi
        print("\nMembuat transaksi di Node A (Alice -> Bob)...")
        # Karena kita belum buat endpoint /transaction, kita akan gunakan script python
        # untuk membuat block langsung di Node A lalu mem-broadcast-nya.
        # (Ini adalah simulasi di mana Node A adalah validatornya).
        
        from voin import VoinChain, StateStore, canonical_tx_message, canonical_block_message
        from eth_account import Account
        from eth_account.messages import encode_defunct
        from security.pqc_signer import generate_keypair, sign as pqc_sign

        # Kita buat dompet dummy untuk Alice dan Validator
        alice_acct = Account.create()
        alice_pk, alice_sk = generate_keypair()
        
        v_acct = Account.create()
        v_pk, v_sk = generate_keypair()

        # Buat instance chain sementara untuk membuat block
        temp_chain = VoinChain(allocations={alice_acct.address: 1000}, difficulty=1, store=StateStore(":memory:"))
        temp_chain.register_validator(v_acct.address, 50, v_acct.address, v_pk.hex())

        tx = {"sender": alice_acct.address, "recipient": "bob", "amount": 250, "nonce": 1}
        msg = canonical_tx_message(tx)
        tx["sig_ecdsa"] = alice_acct.sign_message(encode_defunct(primitive=msg)).signature.hex()
        tx["sig_mldsa"] = pqc_sign(msg, alice_sk).hex()

        # Buat Block
        block = temp_chain.prepare_block([tx], v_acct.address)
        block_msg = canonical_block_message(block)
        v_sig_e = v_acct.sign_message(encode_defunct(primitive=block_msg)).signature.hex()
        v_sig_p = pqc_sign(block_msg, v_sk).hex()

        # 4. Kirim Block dari Node A ke Node B
        print("\nMengirim blok dari Node A ke Node B...")
        payload = {
            "block": block,
            "sig_ecdsa": v_sig_e,
            "sig_mldsa": v_sig_p,
            "sender_node": "External_Simulation"
        }
        res = requests.post(f"{NODE_A_URL}/block", json=payload)
        print(f"Respons Node A: {res.json()}")
        
        # Tunggu broadcast P2P selesai
        time.sleep(1)

        # 5. Cek status akhir
        info_a_end = requests.get(f"{NODE_A_URL}/info").json()
        info_b_end = requests.get(f"{NODE_B_URL}/info").json()
        
        print("\n=== HASIL AKHIR ===")
        print(f"Tinggi Blok Akhir - Node A: {info_a_end['height']}, Node B: {info_b_end['height']}")
        
        if info_a_end['height'] == 1 and info_b_end['height'] == 1:
            print("✅ SUKSES! Node B berhasil menerima dan memvalidasi blok dari Node A via P2P.")
        else:
            print("❌ GAGAL: Sinkronisasi blok antar node tidak berhasil.")

    finally:
        # Matikan node
        print("\nMematikan node...")
        proc_a.terminate()
        proc_b.terminate()
        proc_a.wait()
        proc_b.wait()

if __name__ == "__main__":
    main()
