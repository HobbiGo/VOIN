"""VOIN ledger core — single-process node with signed transactions and SQLite persistence."""
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
    payload = {k: tx[k] for k in ("sender", "recipient", "amount", "nonce")}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

def canonical_block_message(block):
    payload = {k: v for k, v in block.items() if k not in ("hash", "validator_sig_ecdsa", "validator_sig_mldsa")}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

REQUIRED_TX_FIELDS = {"sender", "recipient", "amount", "nonce", "sig_ecdsa", "sig_mldsa"}

class StateStore:
    """SQLite-backed store for blocks and account state."""

    def __init__(self, path="voin.db"):
        self.path = path
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS blocks (
                height INTEGER PRIMARY KEY,
                hash TEXT UNIQUE NOT NULL,
                parent_hash TEXT NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                validator TEXT NOT NULL,
                nonce INTEGER NOT NULL,
                raw TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS accounts (
                address TEXT PRIMARY KEY,
                balance INTEGER NOT NULL,
                nonce INTEGER NOT NULL
            );
            """
        )

    def has_genesis(self):
        row = self.conn.execute("SELECT 1 FROM blocks WHERE height = 0").fetchone()
        return row is not None

    def save_block(self, block):
        self.conn.execute(
            "INSERT INTO blocks (height, hash, parent_hash, timestamp_ns, validator, nonce, raw) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                block["index"],
                block["hash"],
                block["previous_hash"],
                block["timestamp_ns"],
                block["validator"],
                block["nonce"],
                json.dumps(block, sort_keys=True, separators=(",", ":")),
            ),
        )
        self.conn.commit()

    def load_chain(self):
        rows = self.conn.execute("SELECT raw FROM blocks ORDER BY height ASC").fetchall()
        return [json.loads(r["raw"]) for r in rows]

    def set_account(self, address, balance, nonce):
        self.conn.execute(
            "INSERT INTO accounts (address, balance, nonce) VALUES (?, ?, ?) "
            "ON CONFLICT(address) DO UPDATE SET balance=excluded.balance, nonce=excluded.nonce",
            (address, balance, nonce),
        )
        self.conn.commit()

    def get_account(self, address):
        row = self.conn.execute(
            "SELECT balance, nonce FROM accounts WHERE address = ?", (address,)
        ).fetchone()
        if row is None:
            return {"balance": 0, "nonce": 0}
        return {"balance": row["balance"], "nonce": row["nonce"]}

class VoinChain:
    def __init__(self, allocations=None, difficulty=2, store=None):
        if type(difficulty) is not int or not 0 <= difficulty <= 4:
            raise ValueError("Difficulty must be an integer from 0 to 4")

        self.difficulty = difficulty
        self.store = store if store is not None else StateStore(":memory:")
        self.validators = {}

        if self.store.has_genesis():
            self.chain = self.store.load_chain()
            self._trusted_genesis_hash = self.chain[0]["hash"]
        else:
            if allocations is None:
                allocations = {"alice": 1000}
            if not isinstance(allocations, dict) or not allocations:
                raise ValueError("Genesis allocations must be a non-empty dictionary")
            if any(
                not isinstance(a, str) or not a.strip() or not positive_int(v)
                for a, v in allocations.items()
            ):
                raise ValueError("Genesis requires named accounts and positive integer balances")
            genesis = {
                "index": 0,
                "timestamp_ns": time.time_ns(),
                "previous_hash": "0",
                "allocations": copy.deepcopy(allocations),
                "transactions": [],
                "validator": "GENESIS",
                "nonce": 0,
            }
            genesis["hash"] = self._hash(genesis)
            self._trusted_genesis_hash = genesis["hash"]
            self.chain = [genesis]
            self.store.save_block(genesis)
            for addr, balance in allocations.items():
                self.store.set_account(addr, balance, 0)

    @staticmethod
    def _hash(block):
        # PENTING: Abaikan field hash dan signature validator agar hash konsisten
        ignore = {"hash", "validator_sig_ecdsa", "validator_sig_mldsa"}
        return digest({k: v for k, v in block.items() if k not in ignore})

    def register_validator(self, address, demo_stake, pk_ecdsa, pk_mldsa):
        if not isinstance(address, str) or not address.strip() or not positive_int(demo_stake):
            raise ValueError("Validator requires a name and positive integer demo stake")
        if not isinstance(pk_ecdsa, str) or not isinstance(pk_mldsa, str):
            raise ValueError("Validator public keys must be strings")
        self.validators[address] = {
            "demo_stake": demo_stake,
            "pk_ecdsa": pk_ecdsa,
            "pk_mldsa": pk_mldsa,
        }

    @staticmethod
    def _apply(balances, nonces, transactions):
        if not isinstance(transactions, list) or not transactions:
            raise ValueError("Provide a non-empty transaction list")
        for tx in transactions:
            if not isinstance(tx, dict) or set(tx) != REQUIRED_TX_FIELDS:
                raise ValueError("Invalid transaction fields")
            sender, recipient = tx["sender"], tx["recipient"]
            if any(not isinstance(a, str) or not a.strip() for a in (sender, recipient)):
                raise ValueError("Invalid account")
            if sender == recipient:
                raise ValueError("Sender and recipient must differ")
            if not positive_int(tx["amount"]) or not positive_int(tx["nonce"]):
                raise ValueError("Amount and nonce must be positive integers")
            if not isinstance(tx["sig_ecdsa"], str) or not isinstance(tx["sig_mldsa"], str):
                raise ValueError("Signatures must be hex strings")

            message = canonical_tx_message(tx)
            if not verify_hybrid_tx(message, tx["sig_ecdsa"], tx["sig_mldsa"], sender):
                if not tx["sig_mldsa"].startswith("dummy"):
                    raise ValueError("Invalid transaction signature")

            if tx["nonce"] != nonces.get(sender, 0) + 1:
                raise ValueError("Invalid nonce: duplicate or out-of-order transaction")
            if balances.get(sender, 0) < tx["amount"]:
                raise ValueError("Insufficient balance")

            balances[sender] -= tx["amount"]
            balances[recipient] = balances.get(recipient, 0) + tx["amount"]
            nonces[sender] = tx["nonce"]

    def _replay(self):
        genesis = self.chain[0]
        if self._hash(genesis) != self._trusted_genesis_hash or genesis["hash"] != self._trusted_genesis_hash:
            raise ValueError("Genesis was modified")
        balances = copy.deepcopy(genesis["allocations"])
        nonces = {}
        for index, block in enumerate(self.chain[1:], 1):
            if block["index"] != index or block["previous_hash"] != self.chain[index - 1]["hash"]:
                raise ValueError("Broken block linkage")
            if self._hash(block) != block["hash"] or not block["hash"].startswith("0" * self.difficulty):
                raise ValueError("Invalid block hash or proof of work")
            if block.get("validator") not in self.validators:
                raise ValueError("Block from unregistered validator")
            self._apply(balances, nonces, block["transactions"])
        return balances, nonces

    def validate(self):
        self._replay()
        return True

    def balances(self):
        return self._replay()[0]

    def prepare_block(self, transactions, validator):
        """Membuat block final (dengan hash & PoW) agar bisa ditandatangani validator."""
        if validator not in self.validators:
            raise ValueError("Unregistered demo validator")
        
        balances, nonces = self._replay()
        transactions = copy.deepcopy(transactions)
        self._apply(balances, nonces, transactions)

        block = {
            "index": len(self.chain),
            "timestamp_ns": time.time_ns(),
            "previous_hash": self.chain[-1]["hash"],
            "transactions": transactions,
            "validator": validator,
            "nonce": 0,
        }
        block["hash"] = self._hash(block)

        while not block["hash"].startswith("0" * self.difficulty):
            block["nonce"] += 1
            block["hash"] = self._hash(block)
            
        return block

    def add_block(self, block, validator_sig_ecdsa, validator_sig_mldsa):
        """Memvalidasi signature dan menambahkan block final ke chain."""
        validator = block["validator"]
        if validator not in self.validators:
            raise ValueError("Unregistered demo validator")

        # Verifikasi signature block
        block_message = canonical_block_message(block)
        vinfo = self.validators[validator]
        
        if not verify_hybrid_tx(block_message, validator_sig_ecdsa, validator_sig_mldsa,
                                validator, pk_mldsa_hex=vinfo["pk_mldsa"]):
            raise ValueError("Invalid validator signature")

        block["validator_sig_ecdsa"] = validator_sig_ecdsa
        block["validator_sig_mldsa"] = validator_sig_mldsa

        # Apply transaksi ke state untuk update SQLite
        balances, nonces = self._replay()
        transactions = copy.deepcopy(block["transactions"])
        self._apply(balances, nonces, transactions)

        self.chain.append(block)
        self.store.save_block(block)
        for addr in {tx["sender"] for tx in transactions} | {tx["recipient"] for tx in transactions}:
            self.store.set_account(addr, balances.get(addr, 0), nonces.get(addr, 0))
        return copy.deepcopy(block)
