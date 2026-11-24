from __future__ import annotations

import json
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from voin import StateStore, VoinChain

SCHEMA_EXTENSIONS_SQL = """
CREATE TABLE IF NOT EXISTS processed_presale_txs (
    tx_hash TEXT PRIMARY KEY,
    buyer TEXT NOT NULL,
    batch_id INTEGER NOT NULL,
    usd_value_wei TEXT NOT NULL,
    voin_amount_wei TEXT NOT NULL,
    recorded_at_ns INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions_index (
    tx_hash TEXT PRIMARY KEY,
    block_height INTEGER NOT NULL,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    amount INTEGER NOT NULL,
    nonce INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blocks_validator ON blocks(validator);
CREATE INDEX IF NOT EXISTS idx_tx_sender ON transactions_index(sender);
CREATE INDEX IF NOT EXISTS idx_tx_recipient ON transactions_index(recipient);
CREATE INDEX IF NOT EXISTS idx_presale_buyer ON processed_presale_txs(buyer);
"""


def init_database(db_path: str | None = None, genesis_path: str | None = None) -> None:
    target_db = Path(db_path or os.getenv("VOIN_DB_PATH") or (BASE_DIR / "voin.db"))
    target_genesis = Path(genesis_path or (BASE_DIR / "genesis.json"))

    genesis_data = None
    if target_genesis.exists():
        raw = json.loads(target_genesis.read_text(encoding="utf-8"))
        genesis_data = {
            "allocations": raw.get("allocations", {}),
            "validators": raw.get("validators", []),
        }

    store = StateStore(str(target_db))
    store.conn.executescript(SCHEMA_EXTENSIONS_SQL)
    store.conn.commit()

    chain = VoinChain(genesis_data=genesis_data, difficulty=1, store=store)

    # Isi transactions_index bila ada blok yang sudah tersimpan
    for blk in chain.chain[1:]:
        height = blk.get("index", 0)
        for tx in blk.get("transactions", []):
            tx_sig = f"{tx.get('sender','')}:{tx.get('nonce','')}:{blk.get('hash','')}"
            store.conn.execute(
                """
                INSERT OR IGNORE INTO transactions_index
                (tx_hash, block_height, sender, recipient, amount, nonce)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    tx_sig,
                    height,
                    tx.get("sender", ""),
                    tx.get("recipient", ""),
                    int(tx.get("amount", 0)),
                    int(tx.get("nonce", 0)),
                ),
            )
    store.conn.commit()

    tables = [
        r[0]
        for r in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name ASC"
        ).fetchall()
    ]
    print(f"[DB] Berhasil diinisialisasi di: {target_db}")
    print(f"[DB] Tinggi chain saat ini : {len(chain.chain) - 1}")
    print(f"[DB] Tabel tersedia        : {', '.join(tables)}")


if __name__ == "__main__":
    init_database()
