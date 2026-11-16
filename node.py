"""VOIN P2P Node — Mensimulasikan jaringan Layer 1."""
import json
import os
import sys
import time
import threading
import requests
from flask import Flask, jsonify, request
from voin import VoinChain, StateStore, canonical_tx_message, canonical_block_message
from wallet.verification import register_account_keys
from eth_account import Account
from eth_account.messages import encode_defunct
from security.pqc_signer import generate_keypair, sign as pqc_sign

def get_port():
    if len(sys.argv) > 1:
        try: return int(sys.argv[1])
        except ValueError: pass
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

mempool = []
validator_acct = Account.create()
validator_pk_pqc, validator_sk_pqc = generate_keypair()
chain.register_validator(validator_acct.address, 50, validator_acct.address, validator_pk_pqc.hex())

def mine_block():
    while True:
        time.sleep(5)
        if mempool:
            print(f"[{NODE_ID}] ⛏️ Mempool berisi {len(mempool)} transaksi. Membuat blok...")
            txs_to_mine = list(mempool)
            mempool.clear()
            try:
                block = chain.prepare_block(txs_to_mine, validator_acct.address)
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
        "node_id": NODE_ID, "height": len(chain.chain) - 1,
        "peers": list(peers), "mempool_size": len(mempool),
        "validator_address": validator_acct.address
    }), 200

@app.route('/register_key', methods=['POST'])
def register_key():
    data = request.json
    address = data.get("address")
    pk_ecdsa = data.get("pk_ecdsa")
    pk_mldsa = data.get("pk_mldsa")
    if all([address, pk_ecdsa, pk_mldsa]):
        register_account_keys(address, pk_ecdsa, pk_mldsa)
        return jsonify({"message": "Key registered"}), 200
    return jsonify({"error": "Missing keys"}), 400

@app.route('/transaction', methods=['POST'])
def receive_transaction():
    tx = request.json.get("tx")
    sig_ecdsa = request.json.get("sig_ecdsa")
    sig_mldsa = request.json.get("sig_mldsa")

    if not tx or not sig_ecdsa or not sig_mldsa:
        return jsonify({"error": "Missing data"}), 400

    tx["sig_ecdsa"] = sig_ecdsa
    tx["sig_mldsa"] = sig_mldsa

    try:
        # Hanya validasi signature (tanpa mengeksekusi saldo dulu)
        msg = canonical_tx_message(tx)
        from wallet.verification import verify_hybrid_tx
        if not verify_hybrid_tx(msg, sig_ecdsa, sig_mldsa, tx["sender"]):
            return jsonify({"error": "Invalid signature"}), 400
            
        mempool.append(tx)
        print(f"[{NODE_ID}] 📩 Transaksi masuk ke Mempool.")
        return jsonify({"message": "Transaction added to Mempool"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

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
    print(f"Validator Address: {validator_acct.address}")
    app.run(host='0.0.0.0', port=NODE_PORT, debug=False)
