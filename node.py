# node.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from presale_contract import VOINPresaleContract

app = Flask(__name__)
CORS(app)

class BlockchainState:
    def __init__(self):
        self.balances = {}
        self.presale_sold = 0
        self.history = []
        
        # Inisialisasi kuota terjual untuk 10 Batch (0 = belum ada yang terjual)
        self.batch_sold = {i: 0 for i in range(1, 11)}
        self.current_batch = 1

    def add_balance(self, address, amount):
        if address not in self.balances:
            self.balances[address] = 0
        self.balances[address] += amount

    def get_batch_sold(self, batch_number):
        return self.batch_sold.get(batch_number, 0)

    def update_batch_sold(self, batch_number, amount):
        self.batch_sold[batch_number] += amount
        self.presale_sold += amount

    def set_current_batch(self, batch_number):
        self.current_batch = batch_number

    def save_presale_history(self, address, paid, received, batch):
        self.history.append({
            "address": address, "paid": paid, "received": received, "batch": batch
        })

state = BlockchainState()
presale_contract = VOINPresaleContract(state)

@app.route('/api/presale-stats', methods=['GET'])
def get_stats():
    return jsonify({
        "total_supply": presale_contract.total_supply,
        "presale_allocation": presale_contract.presale_allocation,
        "tokens_sold": state.presale_sold,
        "tokens_remaining": presale_contract.presale_allocation - state.presale_sold,
        "current_batch": state.current_batch,
        "batch_details": state.batch_sold
    })

@app.route('/api/buy', methods=['POST'])
def buy_presale():
    data = request.json
    buyer_address = data.get('wallet_address')
    amount_paid = float(data.get('amount_paid', 0))

    if not buyer_address or amount_paid <= 0:
        return jsonify({"status": "error", "message": "Data tidak valid"}), 400

    result = presale_contract.buy_tokens(buyer_address, amount_paid)
    
    if result["status"] == "success":
        return jsonify(result), 200
    else:
        return jsonify(result), 400

if __name__ == '__main__':
    print("🚀 Node VOIN Mainnet (10 Batch System) berjalan...")
    app.run(host='0.0.0.0', port=5000)
