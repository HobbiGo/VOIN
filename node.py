from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from presale_contract import VOINPresaleContract
import os

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


@app.route("/")
def serve_index():
    return send_from_directory(BASE_DIR, "index.html")


class BlockchainState:
    def __init__(self):
        self.balances = {}
        self.presale_sold = 0
        self.history = []

        # Inisialisasi kuota terjual untuk 10 Batch
        self.batch_sold = {i: 0 for i in range(1, 11)}
        self.current_batch = 1

    def add_balance(self, address, amount):
        self.balances[address] = self.balances.get(address, 0) + amount

    def get_batch_sold(self, batch_number):
        return self.batch_sold.get(batch_number, 0)

    def update_batch_sold(self, batch_number, amount):
        self.batch_sold[batch_number] = self.batch_sold.get(batch_number, 0) + amount
        self.presale_sold += amount

    def set_current_batch(self, batch_number):
        self.current_batch = batch_number

    def save_presale_history(self, address, paid, received, batch):
        self.history.append({
            "address": address,
            "paid": paid,
            "received": received,
            "batch": batch,
        })


state = BlockchainState()
presale_contract = VOINPresaleContract(state)


@app.route("/api/presale-stats", methods=["GET"])
def get_stats():
    current_batch = presale_contract.current_batch
    return jsonify({
        "total_supply": presale_contract.total_supply,
        "presale_allocation": presale_contract.presale_allocation,
        "tokens_sold": state.presale_sold,
        "tokens_remaining": max(0, presale_contract.presale_allocation - state.presale_sold),
        "current_batch": current_batch,
        "batch_details": state.batch_sold,
    })


@app.route("/api/buy", methods=["POST"])
def buy_presale():
    data = request.get_json(silent=True) or {}
    buyer_address = str(data.get("wallet_address", "")).strip()

    try:
        amount_paid = float(data.get("amount_paid", 0))
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Jumlah pembayaran tidak valid"}), 400

    if not buyer_address or amount_paid <= 0:
        return jsonify({"status": "error", "message": "Data tidak valid"}), 400

    result = presale_contract.buy_tokens(buyer_address, amount_paid)

    if result.get("status") == "success":
        return jsonify(result), 200
    return jsonify(result), 400


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Node VOIN Mainnet (10 Batch System) berjalan di port {port}...")
    app.run(host="0.0.0.0", port=port)
