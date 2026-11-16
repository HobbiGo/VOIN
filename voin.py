"""VOIN ledger core — single-process node with signed transactions, SQLite persistence, and Smart Contracts."""
import copy
import hashlib
import json
import os
import sqlite3
import time

from security.pqc_signer import verify as pqc_verify
from wallet.verification import verify_hybrid_tx

def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def positive_int(value):
    return type(value) is int and value > 0

def canonical_tx_message(tx):
    # Mengambil semua field penting untuk ditandatangani
    payload = {k: tx[k] for k in ("sender", "recipient", "amount", "nonce", "data")}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

def canonical_block_message(block):
    payload = {k: v for k, v in block.items() if k not in ("hash", "validator_sig_ecdsa", "validator_sig_mldsa")}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

REQUIRED_TX_FIELDS = {"sender", "recipient", "amount", "nonce", "data", "sig_ecdsa", "sig_mldsa"}

class StateStore:
    def __init__(self, path="voin.db"):
        self.path = path
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS blocks (
                height INTEGER PRIMARY KEY, hash TEXT UNIQUE NOT NULL, parent_hash TEXT NOT NULL,
                timestamp_ns INTEGER NOT NULL, validator TEXT NOT NULL, nonce INTEGER NOT NULL, raw TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS accounts (
                address TEXT PRIMARY KEY, balance INTEGER NOT NULL, nonce INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS contracts (
                address TEXT PRIMARY KEY, code TEXT NOT NULL, storage TEXT NOT NULL
            );
            """
        )

    def has_genesis(self):
        return self.conn.execute("SELECT 1 FROM blocks WHERE height = 0").fetchone() is not None

    def save_block(self, block):
        self.conn.execute(
            "INSERT INTO blocks (height, hash, parent_hash, timestamp_ns, validator, nonce, raw) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (block["index"], block["hash"], block["previous_hash"], block["timestamp_ns"], block["validator"], block["nonce"], json.dumps(block, sort_keys=True, separators=(",", ":"))),
        )
        self.conn.commit()

    def load_chain(self):
        return [json.loads(r["raw"]) for r in self.conn.execute("SELECT raw FROM blocks ORDER BY height ASC").fetchall()]

    def set_account(self, address, balance, nonce):
        self.conn.execute(
            "INSERT INTO accounts (address, balance, nonce) VALUES (?, ?, ?) ON CONFLICT(address) DO UPDATE SET balance=excluded.balance, nonce=excluded.nonce",
            (address, balance, nonce),
        )
        self.conn.commit()

    def get_account(self, address):
        row = self.conn.execute("SELECT balance, nonce FROM accounts WHERE address = ?", (address,)).fetchone()
        return {"balance": 0, "nonce": 0} if row is None else {"balance": row["balance"], "nonce": row["nonce"]}

    # --- FUNGSI SMART CONTRACT ---
    def save_contract(self, address, code, storage_data):
        self.conn.execute(
            "INSERT OR REPLACE INTO contracts (address, code, storage) VALUES (?, ?, ?)",
            (address, code, json.dumps(storage_data))
        )
        self.conn.commit()

    def get_contract(self, address):
        row = self.conn.execute("SELECT code, storage FROM contracts WHERE address = ?", (address,)).fetchone()
        return json.loads(row["storage"]) if row else None

class VoinChain:
    def __init__(self, genesis_data=None, difficulty=2, store=None):
        if type(difficulty) is not int or not 0 <= difficulty <= 4:
            raise ValueError("Difficulty must be an integer from 0 to 4")
        self.difficulty = difficulty
        self.store = store if store is not None else StateStore(":memory:")
        self.validators = {}

        if self.store.has_genesis():
            self.chain = self.store.load_chain()
            self._trusted_genesis_hash = self.chain[0]["hash"]
        else:
            allocations = genesis_data.get("allocations", {"alice": 1000}) if genesis_data else {"alice": 1000}
            genesis = {
                "index": 0, "timestamp_ns": time.time_ns(), "previous_hash": "0",
                "allocations": copy.deepcopy(allocations), "transactions": [], "validator": "GENESIS", "nonce": 0,
            }
            genesis["hash"] = self._hash(genesis)
            self._trusted_genesis_hash = genesis["hash"]
            self.chain = [genesis]
            self.store.save_block(genesis)
            for addr, balance in allocations.items():
                self.store.set_account(addr, balance, 0)
                
        if genesis_data and "validators" in genesis_data:
            for v in genesis_data["validators"]:
                self.register_validator(v["address"], 1000000, v["address"], v["pk_mldsa_hex"])

    @staticmethod
    def _hash(block):
        ignore = {"hash", "validator_sig_ecdsa", "validator_sig_mldsa"}
        return digest({k: v for k, v in block.items() if k not in ignore})

    def register_validator(self, address, demo_stake, pk_ecdsa, pk_mldsa):
        self.validators[address] = {"demo_stake": demo_stake, "pk_ecdsa": pk_ecdsa, "pk_mldsa": pk_mldsa}

    def _apply(self, balances, nonces, transactions):
        for tx in transactions:
            if not isinstance(tx, dict) or set(tx) != REQUIRED_TX_FIELDS:
                raise ValueError("Invalid transaction fields")
            sender, recipient = tx["sender"], tx["recipient"]
            
            if not verify_hybrid_tx(canonical_tx_message(tx), tx["sig_ecdsa"], tx["sig_mldsa"], sender):
                raise ValueError("Invalid transaction signature")
            if tx["nonce"] != nonces.get(sender, 0) + 1:
                raise ValueError("Invalid nonce")
            if balances.get(sender, 0) < tx["amount"]:
                raise ValueError("Insufficient balance")

            # --- LOGIKA SMART CONTRACT ---
            data = tx.get("data", {})
            action = data.get("action")

            if action == "deploy":
                # Kontrak baru dibuat di alamat recipient
                contract_code = data.get("code")
                self.store.save_contract(recipient, contract_code, {})
                print(f"[VM] Contract Deployed at {recipient}")
                
            elif action == "call":
                # Memanggil kontrak yang sudah ada
                contract = self.store.get_contract(recipient)
                if not contract:
                    raise ValueError("Contract not found")
                
                # Eksekusi VM Sederhana
                payload = data.get("payload")
                if payload and "message" in payload:
                    # Simulasi kontrak "Messenger" (menyimpan pesan)
                    contract["last_message"] = payload["message"]
                    contract["last_sender"] = sender
                    self.store.save_contract(recipient, "MessengerContract", contract)
                    print(f"[VM] Contract {recipient} executed. Message: {payload['message']}")

            # Transfer saldo (jika ada)
            if tx["amount"] > 0:
                balances[sender] -= tx["amount"]
                balances[recipient] = balances.get(recipient, 0) + tx["amount"]
            
            nonces[sender] = tx["nonce"]

    def _replay(self):
        genesis = self.chain[0]
        balances = copy.deepcopy(genesis["allocations"])
        nonces = {}
        for index, block in enumerate(self.chain[1:], 1):
            self._apply(balances, nonces, block["transactions"])
        return balances, nonces

    def validate(self):
        self._replay()
        return True

    def balances(self):
        return self._replay()[0]

    def prepare_block(self, transactions, validator):
        if validator not in self.validators: raise ValueError("Unregistered validator")
        balances, nonces = self._replay()
        self._apply(balances, nonces, transactions)
        block = {
            "index": len(self.chain), "timestamp_ns": time.time_ns(),
            "previous_hash": self.chain[-1]["hash"], "transactions": copy.deepcopy(transactions),
            "validator": validator, "nonce": 0,
        }
        block["hash"] = self._hash(block)
        while not block["hash"].startswith("0" * self.difficulty):
            block["nonce"] += 1
            block["hash"] = self._hash(block)
        return block

    def add_block(self, block, validator_sig_ecdsa, validator_sig_mldsa):
        validator = block["validator"]
        if validator not in self.validators: raise ValueError("Unregistered validator")
        
        if not verify_hybrid_tx(canonical_block_message(block), validator_sig_ecdsa, validator_sig_mldsa, validator, pk_mldsa_hex=self.validators[validator]["pk_mldsa"]):
            raise ValueError("Invalid validator signature")

        block["validator_sig_ecdsa"] = validator_sig_ecdsa
        block["validator_sig_mldsa"] = validator_sig_mldsa

        balances, nonces = self._replay()
        self._apply(balances, nonces, block["transactions"])

        self.chain.append(block)
        self.store.save_block(block)
        for addr in {tx["sender"] for tx in block["transactions"]} | {tx["recipient"] for tx in block["transactions"]}:
            self.store.set_account(addr, balances.get(addr, 0), nonces.get(addr, 0))
        return copy.deepcopy(block)
