"""VOIN P2P Node — Mensimulasikan jaringan Layer 1 dengan Presale."""
import json
import os
import sys
import time
import threading
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS
from voin import VoinChain, StateStore, canonical_tx_message, canonical_block_message
from wallet.verification import register_account_keys, verify_hybrid_tx
from eth_account import Account
from eth_account.messages import encode_defunct
from security.pqc_signer import generate_keypair, sign as pqc_sign
from presale_contract import VOINPresaleContract

def get_port():
    if len(sys.argv) > 1:
        try: return int(sys.argv[1])
        except ValueError: pass
    return 5000

NODE_PORT = get_port()
NODE_ID = str(NODE_PORT)
DB_FILE = f"voin_node_{NODE_PORT}.db"

# BACA GENESIS
try:
    with open("genesis.json", "r") as f:
        genesis_data = json.load(f)
except FileNotFoundError:
    print("Warning: genesis.json not found. Using default dummy genesis.")
    genesis_data = {"allocations": {"alice": 1000}, "validators": []}

if os.path.exists(DB_FILE) and __name__ == '__main__':
    os.remove(DB_FILE)

app = Flask(__name__)
CORS(app) # Mengizinkan akses dari Dashboard Cloudflare

store = StateStore(DB_FILE)
chain = VoinChain(genesis_data=genesis_data, difficulty=1, store=store)
peers = set()
mempool = []

# Inisialisasi Smart Contract Presale
presale_contract = VOINPresaleContract()

# SETUP VALIDATOR DARI GENESIS
validator_data = genesis_data["validators"][0]
validator_address = validator_data["address"]
validator_acct = Account.create() 
validator_sk_pqc, _ = generate_keypair()

def mine_block():
    while True:
        time.sleep(5)
        if mempool:
            print(f"[{NODE_ID}] ⛏️ Mempool berisi {len(mempool)} transaksi. Membuat blok...")
            txs_to_mine = list(mempool)
            mempool.clear()
            try:
                block = chain.prepare_block(txs_to_mine, validator_address)
                block_msg = canonical_block_message(block)
                
                v_sig_e = validator_acct.sign_message(encode_defunct(primitive=block_msg)).signature.hex()
                v_sig_p = pqc_sign(block_msg, validator_sk_pqc).hex()
                
                chain.add_block(block, v_sig_e, v_sig_p)
                print(f"[{NODE_ID}] ✅ Blok #{block['index']} berhasil ditambang.")
                broadcast_block(block, v_sig_e, v_sig_p)
            except Exception as e:
                print(f"[{NODE_ID}] ❌ Gagal menambang blok: {e}")

if __name__ == '__main__':
    threading.Thread(target=mine_block, daemon=True).start()

@app.route('/info', methods=['GET'])
def get_info():
    return jsonify({
        "node_id": NODE_ID, 
        "height": len(chain.chain) - 1,
        "peers": list(peers), 
        "mempool_size": len(mempool),
        "validator_address": validator_address,
        "treasury_address": presale_contract.treasury_address, # Menampilkan dompet Anda
        "current_batch": presale_contract.current_batch
    }), 200

@app.route('/register_key', methods=['POST'])
def register_key():
    data = request.json
    register_account_keys(data.get("address"), data.get("pk_ecdsa"), data.get("pk_mldsa"))
    return jsonify({"message": "Key registered"}), 200

@app.route('/transaction', methods=['POST'])
def receive_transaction():
    tx = request.json.get("tx")
    tx["sig_ecdsa"] = request.json.get("sig_ecdsa")
    tx["sig_mldsa"] = request.json.get("sig_mldsa")

    # 1. Verifikasi Tanda Tangan
    if not verify_hybrid_tx(canonical_tx_message(tx), tx["sig_ecdsa"], tx["sig_mldsa"], tx["sender"]):
        return jsonify({"error": "Invalid signature"}), 400
        
    # 2. Cek jika ini adalah transaksi pembelian Presale
    if tx["recipient"] == "0xVOIN_PRESALE_CONTRACT_2026":
        usd_amount = tx["data"].get("usd_amount", 0)
        try:
            # Panggil Smart Contract untuk mengeksekusi pembelian
            result = presale_contract.execute(tx["sender"], usd_amount)
            print(f"[{NODE_ID}] 💰 Presale: {tx['sender']} membeli {result['tokens_bought']} VOIN seharga ${usd_amount}")
            print(f"[{NODE_ID}] 🏦 Dana dikirim ke Treasury: {presale_contract.treasury_address}")
            
            # Tambahkan koin VOIN ke saldo pembeli (di ledger L1 kita)
            # (Dalam produksi, ini otomatis dilakukan saat _apply di voin.py)
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    mempool.append(tx)
    print(f"[{NODE_ID}] 📩 Transaksi masuk ke Mempool.")
    return jsonify({"message": "Transaction added to Mempool"}), 200

@app.route('/peers/register', methods=['POST'])
def register_peer():
    peer_address = request.json.get("peer_address")
    if peer_address:
        peers.add(peer_address)
        return jsonify({"message": "Peer registered"}), 201
    return jsonify({"error": "Invalid peer address"}), 400

@app.route('/sync', methods=['GET'])
def sync_chain():
    return jsonify({"chain": chain.chain}), 200

@app.route('/block', methods=['POST'])
def receive_block():
    block_data = request.json.get("block")
    sig_ecdsa = request.json.get("sig_ecdsa")
    sig_mldsa = request.json.get("sig_mldsa")
    sender_node = request.json.get("sender_node")

    if any(b["hash"] == block_data["hash"] for b in chain.chain):
        return jsonify({"message": "Block already known"}), 200
    if block_data["index"] != len(chain.chain):
        return jsonify({"error": "Block out of order"}), 400

    try:
        chain.add_block(block_data, sig_ecdsa, sig_mldsa)
        print(f"[{NODE_ID}] Menerima blok baru #{block_data['index']} dari {sender_node}")
        broadcast_block(block_data, sig_ecdsa, sig_mldsa, exclude_node=sender_node)
        return jsonify({"message": "Block accepted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

def broadcast_block(block_data, sig_ecdsa, sig_mldsa, exclude_node=None):
    for peer in peers:
        if peer == exclude_node: continue
        try:
            requests.post(f"{peer}/block", json={
                "block": block_data, "sig_ecdsa": sig_ecdsa,
                "sig_mldsa": sig_mldsa, "sender_node": NODE_ID
            }, timeout=2)
        except requests.exceptions.RequestException:
            pass

if __name__ == '__main__':
    print(f"=== VOIN NODE {NODE_ID} MENYALA DI PORT {NODE_PORT} ===")
    print(f"Genesis Validator: {validator_address}")
    print(f"Dompet Penerima Dana (Treasury): {presale_contract.treasury_address}")
    app.run(host='0.0.0.0', port=NODE_PORT, debug=False)
