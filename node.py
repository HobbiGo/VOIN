"""VOIN P2P Node — Mensimulasikan jaringan Layer 1."""
import json
import os
import sys
import time
import requests
from flask import Flask, jsonify, request
from voin import VoinChain, StateStore, canonical_tx_message, canonical_block_message

def get_port():
    if len(sys.argv) > 1:
        try:
            return int(sys.argv[1])
        except ValueError:
            pass
    return 5000

NODE_PORT = get_port()
NODE_ID = str(NODE_PORT)
DB_FILE = f"voin_node_{NODE_PORT}.db"

if os.path.exists(DB_FILE) and __name__ == '__main__':
    os.remove(DB_FILE)

app = Flask(__name__)
store = StateStore(DB_FILE)
chain = VoinChain(allocations={"alice": 1000}, difficulty=1, store=store)
peers = set()

# ==========================================
# ENDPOINT API (BARU: /transaction & /balance)
# ==========================================

@app.route('/info', methods=['GET'])
def get_info():
    return jsonify({
        "node_id": NODE_ID,
        "height": len(chain.chain) - 1,
        "peers": list(peers),
        "last_block_hash": chain.chain[-1]["hash"]
    }), 200

@app.route('/balance/<address>', methods=['GET'])
def get_balance(address):
    balances = chain.balances()
    return jsonify({"address": address, "balance": balances.get(address, 0)}), 200

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

@app.route('/transaction', methods=['POST'])
def receive_transaction():
    """Menerima transaksi dari Wallet, memvalidasi, lalu membuat blok baru."""
    tx = request.json.get("tx")
    sig_ecdsa = request.json.get("sig_ecdsa")
    sig_mldsa = request.json.get("sig_mldsa")
    validator_id = request.json.get("validator_id")
    validator_sig_ecdsa = request.json.get("validator_sig_ecdsa")
    validator_sig_mldsa = request.json.get("validator_sig_mldsa")

    if not all([tx, sig_ecdsa, sig_mldsa, validator_id]):
        return jsonify({"error": "Missing transaction data"}), 400

    # Sisipkan signature ke dalam objek tx
    tx["sig_ecdsa"] = sig_ecdsa
    tx["sig_mldsa"] = sig_mldsa

    try:
        # 1. Siapkan blok (Akan otomatis memvalidasi signature transaksi via voin.py)
        block = chain.prepare_block([tx], validator_id)
        
        # 2. Tanda tangani blok (Di produksi, ini dilakukan oleh Node Validator. 
        # Di sini, wallet mengirimkan signature validator agar node bisa memprosesnya)
        block_msg = canonical_block_message(block)
        
        # 3. Tambahkan blok ke chain
        chain.add_block(block, validator_sig_ecdsa, validator_sig_mldsa)
        
        print(f"[{NODE_ID}] Transaksi berhasil dimasukkan ke blok #{block['index']}")
        
        # 4. Broadcast ke peer lain
        broadcast_block(block, validator_sig_ecdsa, validator_sig_mldsa)
        
        return jsonify({"message": "Transaction accepted", "block_hash": block["hash"]}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/block', methods=['POST'])
def receive_block():
    block_data = request.json.get("block")
    sig_ecdsa = request.json.get("sig_ecdsa")
    sig_mldsa = request.json.get("sig_mldsa")
    sender_node = request.json.get("sender_node")

    if not block_data or not sig_ecdsa or not sig_mldsa:
        return jsonify({"error": "Missing data"}), 400

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
    app.run(host='0.0.0.0', port=NODE_PORT, debug=False)
