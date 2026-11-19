# node.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os

# Import kontrak presale kita
from presale_contract import VOINPresaleContract

app = Flask(__name__)
CORS(app) # Agar website HTML bisa akses API ini

# Simulasi State (Di produksi asli, ini terhubung ke database seperti PostgreSQL)
class BlockchainState:
    def __init__(self):
        self.balances = {}
        self.presale_sold = 0
        self.history = []

    def add_balance(self, address, amount):
        if address not in self.balances:
            self.balances[address] = 0
        self.balances[address] += amount

    def deduct_balance(self, address, amount):
        if self.balances.get(address, 0) >= amount:
            self.balances[address] -= amount
            return True
        return False
        
    def update_presale_sold(self, total_sold):
        self.presale_sold = total_sold

    def save_presale_history(self, address, paid, received):
        self.history.append({
            "address": address, "paid": paid, "received": received
        })

# Inisialisasi State & Kontrak
state = BlockchainState()
presale_contract = VOINPresaleContract(state)

# ==========================================
# ENDPOINT API UNTUK WEBSITE PRESALE
# ==========================================

@app.route('/api/presale-stats', methods=['GET'])
def get_stats():
    """Untuk menampilkan sisa kuota di website"""
    return jsonify({
        "total_supply": presale_contract.total_supply,
        "presale_allocation": presale_contract.presale_allocation,
        "tokens_sold": presale_contract.tokens_sold,
        "tokens_remaining": presale_contract.presale_allocation - presale_contract.tokens_sold
    })

@app.route('/api/buy', methods=['POST'])
def buy_presale():
    """Endpoint saat user klik tombol Beli di website"""
    data = request.json
    buyer_address = data.get('wallet_address')
    amount_paid = float(data.get('amount_paid', 0))

    if not buyer_address or amount_paid <= 0:
        return jsonify({"status": "error", "message": "Data tidak valid"}), 400

    # Panggil Smart Contract
    result = presale_contract.buy_tokens(buyer_address, amount_paid)
    
    if result["status"] == "success":
        return jsonify(result), 200
    else:
        return jsonify(result), 400

if __name__ == '__main__':
    print("🚀 Node VOIN Mainnet berjalan di port 5000...")
    app.run(host='0.0.0.0', port=5000)
