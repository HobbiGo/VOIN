import hmac
import json
import os
import sys
import threading

import requests
from eth_account import Account
from eth_account.messages import encode_defunct
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from presale_contract import VOINPresaleContract
from security.pqc_signer import generate_keypair, sign as pqc_sign
from voin import (
    REQUIRED_TX_FIELDS,
    StateStore,
    VoinChain,
    canonical_block_message,
)
from blockchain.transaction_verifier import BlockchainTransactionVerifier

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
API_TOKEN = (os.getenv("API_TOKEN") or "").strip()

DB_PATH = os.getenv("VOIN_DB_PATH", os.path.join(BASE_DIR, "voin.db"))
SKIP_ONCHAIN_VERIFICATION = os.getenv("SKIP_ONCHAIN_VERIFICATION", "false").lower() == "true"

# ============================================================
# 1. PRESALE STATE & CONTRACT
# ============================================================
class BlockchainState:
    def __init__(self):
        self.balances = {}
        self.presale_sold = 0
        self.history = []
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


presale_state = BlockchainState()
presale_contract = VOINPresaleContract(presale_state)

# ============================================================
# 2. BLOCKCHAIN L1 STATE
# ============================================================
store = StateStore(DB_PATH)

genesis_data = None
genesis_path = os.path.join(BASE_DIR, "genesis.json")
if os.path.exists(genesis_path) and not store.has_genesis():
    with open(genesis_path, "r", encoding="utf-8") as f:
        raw_genesis = json.load(f)
    genesis_data = {
        "allocations": raw_genesis.get("allocations", {"alice": 1000}),
        "validators": raw_genesis.get("validators", []),
    }

chain = VoinChain(genesis_data=genesis_data, difficulty=1, store=store)
PEERS = set()
LOCK = threading.Lock()

verifier = BlockchainTransactionVerifier(
    rpc_url=os.getenv("BSC_RPC_URL", "https://data-seed-prebsc-1-s1.binance.org:8545/"),
    presale_contract_address=os.getenv("VOIN_PRESALE_CONTRACT", ""),
    treasury_address=os.getenv("TREASURY_ADDRESS", "0xAEb22359588A50e6F746004E66418Eb2c978dAA2"),
    expected_chain_id=int(os.getenv("EXPECTED_CHAIN_ID", "97")),
)

if not SKIP_ONCHAIN_VERIFICATION and not verifier.presale_contract:
    print("[WARNING] VOIN_PRESALE_CONTRACT belum diset. Verifikasi on-chain akan gagal!")

_DEV_VALIDATOR_ACCT = None
_DEV_VALIDATOR_SK = None
if not chain.validators:
    _dev_acct = Account.create()
    try:
        _dev_pk, _dev_sk = generate_keypair()
        chain.register_validator(_dev_acct.address, 1_000_000, _dev_acct.address, _dev_pk.hex())
        _DEV_VALIDATOR_ACCT = _dev_acct
        _DEV_VALIDATOR_SK = _dev_sk
        print(f"[DEV] Validator default terdaftar: {_dev_acct.address}")
    except Exception as exc:
        print(f"[DEV] Gagal membuat validator default: {exc}")

# ============================================================
# 3. HELPER FUNCTIONS
# ============================================================
def _to_canonical_bytes(msg) -> bytes:
    if isinstance(msg, (bytes, bytearray)):
        return bytes(msg)
    if isinstance(msg, str):
        return msg.encode("utf-8")
    return json.dumps(msg, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _normalize_hex_sig(sig) -> str:
    if isinstance(sig, (bytes, bytearray)):
        hex_str = bytes(sig).hex()
    else:
        hex_str = str(sig).strip()
        if hex_str.startswith(("0x", "0X")):
            hex_str = hex_str[2:]
    return f"0x{hex_str}"


def _is_authorized() -> bool:
    if not API_TOKEN:
        return True
    auth_header = (request.headers.get("Authorization") or "").strip()
    bearer_token = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
    x_token = (request.headers.get("X-API-Token") or "").strip()
    candidate = bearer_token or x_token
    return hmac.compare_digest(candidate, API_TOKEN) if candidate else False


def _broadcast_block_to_peers(block, sig_e, sig_p, skip_peer=None):
    payload = {
        "block": block,
        "sig_ecdsa": sig_e,
        "sig_mldsa": sig_p,
        "sender_node": request.host_url,
    }
    for peer in list(PEERS):
        if peer == skip_peer:
            continue
        try:
            requests.post(f"{peer.rstrip('/')}/block", json=payload, timeout=3)
        except Exception as exc:
            print(f"[P2P] Gagal broadcast ke {peer}: {exc}")

# ============================================================
# 4. FLASK APP & ROUTES
# ============================================================
app = Flask(__name__)
CORS(app)


@app.route("/")
def serve_index():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/<path:filename>")
def serve_static(filename):
    safe = os.path.normpath(filename)
    if safe.startswith("..") or os.path.isabs(safe):
        return jsonify({"error": "invalid path"}), 400
    return send_from_directory(BASE_DIR, safe)


@app.route("/api/presale-stats", methods=["GET"])
def get_stats():
    return jsonify({
        "total_supply": presale_contract.total_supply,
        "presale_allocation": presale_contract.presale_allocation,
        "tokens_sold": presale_state.presale_sold,
        "tokens_remaining": max(0, presale_contract.presale_allocation - presale_state.presale_sold),
        "current_batch": presale_contract.current_batch,
        "batch_details": presale_state.batch_sold,
        "batch_prices_usd": presale_contract.batch_prices_usd,
    })


@app.route("/api/buy", methods=["POST"])
def buy_presale():
    if not _is_authorized():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    buyer_address = str(data.get("wallet_address", "")).strip()
    tx_hash = str(data.get("tx_hash", "")).strip()
    try:
        claimed_amount = float(data.get("amount_paid", 0))
    except (TypeError, ValueError):
        claimed_amount = 0.0

    if not buyer_address:
        return jsonify({"status": "error", "message": "Wallet address required"}), 400

    amount_to_process = claimed_amount
    if not SKIP_ONCHAIN_VERIFICATION:
        if not tx_hash:
            return jsonify({"status": "error", "message": "tx_hash BSC wajib dikirim."}), 400

        print(f"[VERIFIER] Memeriksa tx {tx_hash} untuk {buyer_address}...")
        res = verifier.verify_presale_transaction(tx_hash=tx_hash, expected_buyer=buyer_address)
        if not res.valid:
            return jsonify({"status": "failed", "reason": f"Verifikasi Gagal: {res.reason}"}), 400

        usd_wei = getattr(res, "usd_value_wei", None)
        if usd_wei is None:
            return jsonify({"status": "failed", "reason": "Verifikasi Gagal: nilai USD tidak tersedia."}), 400

        amount_to_process = float(usd_wei) / 1e18
        print(f"[VERIFIER] Sukses! Pembayaran valid: ${amount_to_process}")

    result = presale_contract.buy_tokens(buyer_address, amount_to_process)
    if result.get("status") == "success":
        result["verified_tx_hash"] = tx_hash if not SKIP_ONCHAIN_VERIFICATION else "bypassed"
        return jsonify(result), 200
    return jsonify(result), 400


@app.route("/info", methods=["GET"])
def info():
    return jsonify({
        "network": "VOIN",
        "height": len(chain.chain) - 1,
        "difficulty": chain.difficulty,
        "validators": list(chain.validators.keys()),
        "peers": list(PEERS),
        "genesis_hash": chain.chain[0]["hash"],
    })


@app.route("/sync", methods=["GET"])
def sync():
    return jsonify({"height": len(chain.chain) - 1, "chain": chain.chain})


@app.route("/balance/<address>", methods=["GET"])
def balance(address):
    balances = chain.balances()
    return jsonify({
        "address": address,
        "balance": balances.get(address, 0),
        "nonce": chain.store.get_account(address).get("nonce", 0),
    })


@app.route("/transaction", methods=["POST"])
def submit_transaction():
    if not _is_authorized():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    body = request.get_json(silent=True) or {}
    tx_raw = body.get("tx")
    if not isinstance(tx_raw, dict):
        return jsonify({"ok": False, "error": "tx harus object"}), 400

    tx = dict(tx_raw)
    if "sig_ecdsa" not in tx and body.get("sig_ecdsa"):
        tx["sig_ecdsa"] = body["sig_ecdsa"]
    if "sig_mldsa" not in tx and body.get("sig_mldsa"):
        tx["sig_mldsa"] = body["sig_mldsa"]

    if set(tx) != REQUIRED_TX_FIELDS:
        missing = REQUIRED_TX_FIELDS - set(tx)
        extra = set(tx) - REQUIRED_TX_FIELDS
        return jsonify({
            "ok": False,
            "error": "field tx tidak sesuai",
            "missing": sorted(missing),
            "extra": sorted(extra),
        }), 400

    validator_id = (body.get("validator_id") or "").strip()
    if not validator_id:
        if _DEV_VALIDATOR_ACCT is not None:
            validator_id = _DEV_VALIDATOR_ACCT.address
        elif chain.validators:
            validator_id = next(iter(chain.validators.keys()))

    if not validator_id or validator_id not in chain.validators:
        return jsonify({"ok": False, "error": "validator_id tidak terdaftar"}), 400

    with LOCK:
        try:
            block = chain.prepare_block([tx], validator_id)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        sig_e = body.get("validator_sig_ecdsa")
        sig_p = body.get("validator_sig_mldsa")

        if not sig_e or not sig_p:
            if _DEV_VALIDATOR_ACCT and _DEV_VALIDATOR_SK and validator_id == _DEV_VALIDATOR_ACCT.address:
                block_bytes = _to_canonical_bytes(canonical_block_message(block))
                sig_e = _normalize_hex_sig(
                    _DEV_VALIDATOR_ACCT.sign_message(encode_defunct(primitive=block_bytes)).signature
                )
                sig_p = _normalize_hex_sig(pqc_sign(block_bytes, _DEV_VALIDATOR_SK))
            else:
                return jsonify({"ok": False, "error": "validator_sig wajib dikirim untuk validator eksternal"}), 400

        try:
            added = chain.add_block(block, sig_e, sig_p)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        _broadcast_block_to_peers(added, sig_e, sig_p)

    return jsonify({
        "ok": True,
        "block_index": added["index"],
        "block_hash": added["hash"],
        "tx_count": len(added["transactions"]),
    })


@app.route("/block", methods=["POST"])
def receive_block():
    body = request.get_json(silent=True) or {}
    block, sig_e, sig_p = body.get("block"), body.get("sig_ecdsa"), body.get("sig_mldsa")
    if not isinstance(block, dict) or not sig_e or not sig_p:
        return jsonify({"ok": False, "error": "payload tidak lengkap"}), 400

    with LOCK:
        if block["index"] <= len(chain.chain) - 1:
            return jsonify({"ok": True, "message": "block sudah ada"})
        if block["index"] != len(chain.chain) or block["previous_hash"] != chain.chain[-1]["hash"]:
            return jsonify({"ok": False, "error": "index/previous_hash tidak cocok"}), 400
        try:
            added = chain.add_block(block, sig_e, sig_p)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        _broadcast_block_to_peers(added, sig_e, sig_p, skip_peer=body.get("sender_node"))

    return jsonify({"ok": True, "block_index": added["index"]})


@app.route("/peers/register", methods=["POST"])
def register_peer():
    if not _is_authorized():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    peer = (request.get_json(silent=True) or {}).get("peer_address", "").strip().rstrip("/")
    if not peer:
        return jsonify({"ok": False, "error": "peer_address kosong"}), 400
    PEERS.add(peer)
    return jsonify({"ok": True, "peers": list(PEERS)})


@app.route("/peers", methods=["GET"])
def list_peers():
    return jsonify({"peers": list(PEERS)})

# ============================================================
# 5. MAIN
# ============================================================
if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", 5000))
    print(f"Node VOIN berjalan di port {port}...")
    print(f"DB: {DB_PATH}")
    print(f"On-chain Verification: {'DISABLED (Bypass)' if SKIP_ONCHAIN_VERIFICATION else 'ENABLED'}")
    app.run(host="0.0.0.0", port=port, threaded=True)
