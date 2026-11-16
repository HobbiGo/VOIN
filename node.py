"""VOIN P2P Node — Mensimulasikan jaringan Layer 1."""
import json
import os
import sys
import time
import requests
from flask import Flask, jsonify, request
from voin import VoinChain, StateStore

# ==========================================
# KONFIGURASI NODE
# ==========================================
NODE_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
NODE_ID = str(NODE_PORT)
DB_FILE = f"voin_node_{NODE_PORT}.db"

# Hapus DB lama jika ada (untuk testing bersih)
if os.path.exists(DB_FILE):
    os.remove(DB_FILE)

app = Flask(__name__)
store = StateStore(DB_FILE)
# Inisialisasi rantai dengan saldo awal di genesis
chain = VoinChain(allocations={"alice": 1000}, difficulty=1, store=store)

# Daftar node lain yang terhubung (Peer)
peers = set()

# ==========================================
# ENDPOINT API
# ==========================================

@app.route('/info', methods=['GET'])
def get_info():
    return jsonify({
        "node_id": NODE_ID,
        "height": len(chain.chain) - 1,
        "peers": list(peers),
        "last_block_hash": chain.chain[-1]["hash"]
    }), 200

@app.route('/peers/register', methods=['POST'])
def register_peer():
    """Node lain mendaftar ke kita."""
    peer_address = request.json.get("peer_address")
    if peer_address:
        peers.add(peer_address)
        print(f"[{NODE_ID}] Peer baru terhubung: {peer_address}")
        return jsonify({"message": "Peer registered"}), 201
    return jsonify({"error": "Invalid peer address"}), 400

@app.route('/sync', methods=['GET'])
def sync_chain():
    """Mengirim seluruh rantai blok ke node yang meminta."""
    return jsonify({"chain": chain.chain}), 200

@app.route('/block', methods=['POST'])
def receive_block():
    """Menerima blok baru dari node lain (Consensus)."""
    block_data = request.json.get("block")
    sig_ecdsa = request.json.get("sig_ecdsa")
    sig_mldsa = request.json.get("sig_mldsa")
    sender_node = request.json.get("sender_node")

    if not block_data or not sig_ecdsa or not sig_mldsa:
        return jsonify({"error": "Missing data"}), 400

    # Cek apakah blok ini sudah ada
    if any(b["hash"] == block_data["hash"] for b in chain.chain):
        return jsonify({"message": "Block already known"}), 200

    # Cek apakah index blok sesuai
    if block_data["index"] != len(chain.chain):
        return jsonify({"error": "Block out of order"}), 400

    try:
        # Validasi dan tambahkan blok (VoinChain akan mengecek signature validator)
        chain.add_block(block_data, sig_ecdsa, sig_mldsa)
        print(f"[{NODE_ID}] Menerima blok baru #{block_data['index']} dari Node {sender_node}")
        
        # Teruskan blok ke peer lain (Gossip Protocol)
        broadcast_block(block_data, sig_ecdsa, sig_mldsa, exclude_node=sender_node)
        
        return jsonify({"message": "Block accepted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ==========================================
# FUNGSI JARINGAN
# ==========================================

def broadcast_block(block_data, sig_ecdsa, sig_mldsa, exclude_node=None):
    """Mengirim blok ke semua peer yang terhubung."""
    for peer in peers:
        if peer == exclude_node:
            continue
        try:
            requests.post(f"{peer}/block", json={
                "block": block_data,
                "sig_ecdsa": sig_ecdsa,
                "sig_mldsa": sig_mldsa,
                "sender_node": NODE_ID
            }, timeout=2)
        except requests.exceptions.RequestException:
            pass # Abaikan jika peer mati

def sync_with_peers():
    """Meminta rantai terbaru dari semua peer."""
    global chain
    longest_chain = chain.chain
    for peer in peers:
        try:
            response = requests.get(f"{peer}/sync", timeout=2)
            if response.status_code == 200:
                peer_chain = response.json()["chain"]
                if len(peer_chain) > len(longest_chain):
                    longest_chain = peer_chain
        except requests.exceptions.RequestException:
            pass
            
    if len(longest_chain) > len(chain.chain):
        print(f"[{NODE_ID}] Sinkronisasi: Menemukan rantai lebih panjang dari peer.")
        # Di produksi, kita harus memvalidasi ulang seluruh rantai di sini.
        # Untuk simulasi, kita langsung ganti.
        chain.chain = longest_chain

# ==========================================
# MAIN
# ==========================================
if __name__ == '__main__':
    print(f"=== VOIN NODE {NODE_ID} MENYALA DI PORT {NODE_PORT} ===")
    print(f"Database: {DB_FILE}")
    # Jalankan Flask
    app.run(host='0.0.0.0', port=NODE_PORT, debug=False)
