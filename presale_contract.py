from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


DEFAULT_TREASURY_ADDRESS = "0xAEb22359588A50e6F746004E66418Eb2c978dAA2"
DEFAULT_RPC_URL = os.getenv("BSC_RPC_URL", "https://data-seed-prebsc-1-s1.binance.org:8545/")

# Jadwal presale: 1 Desember 2026 00:00:00 UTC s/d 31 Desember 2028 23:59:59 UTC
PRESALE_START_TIMESTAMP = 1796083200
PRESALE_END_TIMESTAMP = 1861919999

# Batas pembelian per wallet per batch (skala 1e18 USD)
MIN_PURCHASE_USD_WEI = 25 * (10**18)
MAX_PURCHASE_USD_PER_BATCH_WEI = 10_000 * (10**18)

# Kuota & harga terkunci per batch (10 batch x 15,600,000 VOIN = 156,000,000 VOIN)
BATCH_VOIN_ALLOCATION = 15_600_000.0
TOTAL_BATCHES = 10

BATCH_PRICES_USD: Dict[int, float] = {
    1: 0.01,
    2: 0.02,
    3: 0.03,
    4: 0.04,
    5: 0.05,
    6: 0.06,
    7: 0.07,
    8: 0.08,
    9: 0.09,
    10: 0.10,
}

# Keccak-256 topic0 untuk event:
# TokensPurchased(address,address,uint256,uint256,uint256,uint256,uint256)
TOKENS_PURCHASED_TOPIC0 = os.getenv("VOIN_TOKENS_PURCHASED_TOPIC0", "")


@dataclass
class VerificationResult:
    valid: bool
    tx_hash: str
    chain_id: Optional[int] = None
    block_number: Optional[int] = None
    buyer: Optional[str] = None
    payment_token: Optional[str] = None
    amount_paid_raw: Optional[int] = None
    usd_value_wei: Optional[int] = None
    voin_amount_wei: Optional[int] = None
    batch_id: Optional[int] = None
    timestamp: Optional[int] = None
    reason: str = ""


def normalize_address(addr: Optional[str]) -> str:
    if not addr or not isinstance(addr, str):
        return ""
    cleaned = addr.strip()
    if not cleaned.startswith("0x") or len(cleaned) != 42:
        return ""
    return cleaned.lower()


def is_valid_tx_hash(tx_hash: str) -> bool:
    if not isinstance(tx_hash, str):
        return False
    h = tx_hash.strip()
    if not h.startswith("0x") or len(h) != 66:
        return False
    try:
        int(h[2:], 16)
        return True
    except ValueError:
        return False


class BlockchainTransactionVerifier:
    def __init__(
        self,
        rpc_url: str = DEFAULT_RPC_URL,
        presale_contract_address: str = "",
        treasury_address: str = DEFAULT_TREASURY_ADDRESS,
        expected_chain_id: Optional[int] = None,
        timeout_seconds: int = 15,
    ) -> None:
        self.rpc_url = rpc_url
        self.presale_contract = normalize_address(presale_contract_address)
        self.treasury_address = normalize_address(treasury_address)
        self.expected_chain_id = expected_chain_id
        self.timeout_seconds = timeout_seconds

    def _rpc_call(self, method: str, params: List[Any]) -> Any:
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }).encode("utf-8")

        req = urllib.request.Request(
            self.rpc_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"RPC call failed ({method}): {exc}") from exc

        if "error" in body and body["error"] is not None:
            raise RuntimeError(f"RPC error ({method}): {body['error']}")
        return body.get("result")

    def get_chain_id(self) -> int:
        res = self._rpc_call("eth_chainId", [])
        return int(res, 16)

    def get_transaction_receipt(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        return self._rpc_call("eth_getTransactionReceipt", [tx_hash])

    def get_block_timestamp(self, block_number_hex: str) -> Optional[int]:
        block = self._rpc_call("eth_getBlockByNumber", [block_number_hex, False])
        if not block or "timestamp" not in block:
            return None
        return int(block["timestamp"], 16)

    @staticmethod
    def _decode_indexed_address(topic_hex: str) -> str:
        if not topic_hex or len(topic_hex) < 42:
            return ""
        return "0x" + topic_hex[-40:].lower()

    @staticmethod
    def _decode_uint256_words(data_hex: str) -> List[int]:
        raw = data_hex[2:] if data_hex.startswith("0x") else data_hex
        if len(raw) % 64 != 0:
            raise ValueError("Invalid ABI data length")
        words: List[int] = []
        for i in range(0, len(raw), 64):
            words.append(int(raw[i : i + 64], 16))
        return words

    def _parse_tokens_purchased_log(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        topics = log.get("topics") or []
        if len(topics) < 4:
            return None

        if TOKENS_PURCHASED_TOPIC0:
            if topics[0].lower() != TOKENS_PURCHASED_TOPIC0.lower():
                return None

        buyer = self._decode_indexed_address(topics[1])
        payment_token = self._decode_indexed_address(topics[2])
        batch_id = int(topics[3], 16)

        words = self._decode_uint256_words(log.get("data", "0x"))
        if len(words) < 4:
            return None

        return {
            "buyer": buyer,
            "payment_token": payment_token,
            "batch_id": batch_id,
            "amount_paid_raw": words[0],
            "usd_value_wei": words[1],
            "voin_amount_wei": words[2],
            "timestamp": words[3],
        }

    def verify_presale_transaction(
        self,
        tx_hash: str,
        expected_buyer: Optional[str] = None,
        existing_batch_spent_usd_wei: int = 0,
    ) -> VerificationResult:
        if not is_valid_tx_hash(tx_hash):
            return VerificationResult(valid=False, tx_hash=tx_hash, reason="Invalid tx_hash format")

        normalized_hash = tx_hash.strip().lower()

        try:
            chain_id = self.get_chain_id()
            if self.expected_chain_id is not None and chain_id != self.expected_chain_id:
                return VerificationResult(
                    valid=False,
                    tx_hash=normalized_hash,
                    chain_id=chain_id,
                    reason=f"Chain ID mismatch: got {chain_id}, expected {self.expected_chain_id}",
                )

            receipt = self.get_transaction_receipt(normalized_hash)
            if not receipt:
                return VerificationResult(
                    valid=False,
                    tx_hash=normalized_hash,
                    chain_id=chain_id,
                    reason="Transaction receipt not found (pending or nonexistent)",
                )

            status_hex = receipt.get("status", "0x0")
            if int(status_hex, 16) != 1:
                return VerificationResult(
                    valid=False,
                    tx_hash=normalized_hash,
                    chain_id=chain_id,
                    reason="Transaction reverted on-chain",
                )

            block_num_hex = receipt.get("blockNumber", "0x0")
            block_number = int(block_num_hex, 16)
            block_ts = self.get_block_timestamp(block_num_hex)

            if block_ts is not None:
                if block_ts < PRESALE_START_TIMESTAMP:
                    return VerificationResult(
                        valid=False,
                        tx_hash=normalized_hash,
                        chain_id=chain_id,
                        block_number=block_number,
                        timestamp=block_ts,
                        reason="Transaction timestamp is before presale start (2026-12-01 UTC)",
                    )
                if block_ts > PRESALE_END_TIMESTAMP:
                    return VerificationResult(
                        valid=False,
                        tx_hash=normalized_hash,
                        chain_id=chain_id,
                        block_number=block_number,
                        timestamp=block_ts,
                        reason="Transaction timestamp is after presale end (2028-12-31 UTC)",
                    )

            logs = receipt.get("logs") or []
            parsed_event: Optional[Dict[str, Any]] = None
            for log in logs:
                log_addr = normalize_address(log.get("address"))
                if self.presale_contract and log_addr != self.presale_contract:
                    continue
                candidate = self._parse_tokens_purchased_log(log)
                if candidate is not None:
                    parsed_event = candidate
                    break

            if not parsed_event:
                return VerificationResult(
                    valid=False,
                    tx_hash=normalized_hash,
                    chain_id=chain_id,
                    block_number=block_number,
                    timestamp=block_ts,
                    reason="No valid TokensPurchased event found for presale contract",
                )

            buyer = parsed_event["buyer"]
            if expected_buyer and normalize_address(expected_buyer) != buyer:
                return VerificationResult(
                    valid=False,
                    tx_hash=normalized_hash,
                    chain_id=chain_id,
                    block_number=block_number,
                    buyer=buyer,
                    reason="Buyer address does not match expected wallet",
                )

            usd_value_wei = parsed_event["usd_value_wei"]
            if usd_value_wei < MIN_PURCHASE_USD_WEI:
                return VerificationResult(
                    valid=False,
                    tx_hash=normalized_hash,
                    chain_id=chain_id,
                    block_number=block_number,
                    buyer=buyer,
                    usd_value_wei=usd_value_wei,
                    reason="Purchase below $25 minimum",
                )

            if existing_batch_spent_usd_wei + usd_value_wei > MAX_PURCHASE_USD_PER_BATCH_WEI:
                return VerificationResult(
                    valid=False,
                    tx_hash=normalized_hash,
                    chain_id=chain_id,
                    block_number=block_number,
                    buyer=buyer,
                    usd_value_wei=usd_value_wei,
                    reason="Purchase exceeds $10,000 max per wallet per batch",
                )

            return VerificationResult(
                valid=True,
                tx_hash=normalized_hash,
                chain_id=chain_id,
                block_number=block_number,
                buyer=buyer,
                payment_token=parsed_event["payment_token"],
                amount_paid_raw=parsed_event["amount_paid_raw"],
                usd_value_wei=usd_value_wei,
                voin_amount_wei=parsed_event["voin_amount_wei"],
                batch_id=parsed_event["batch_id"],
                timestamp=parsed_event["timestamp"] or block_ts,
                reason="Verified on-chain",
            )

        except Exception as exc:
            return VerificationResult(
                valid=False,
                tx_hash=normalized_hash,
                reason=str(exc),
            )


class PresaleService:
    """Mengelola kuota 10 batch, batas per wallet per batch, dan riwayat pembelian."""

    def __init__(
        self,
        verifier: BlockchainTransactionVerifier,
        state_file: str = "presale_state.json",
        require_tx_hash: bool = False,
    ) -> None:
        self.verifier = verifier
        self.state_file = state_file
        self.require_tx_hash = require_tx_hash
        self._lock = threading.Lock()

        self.current_batch: int = 1
        self.batch_sold_voin: Dict[int, float] = {b: 0.0 for b in range(1, TOTAL_BATCHES + 1)}
        self.wallet_batch_spent_usd: Dict[Tuple[str, int], float] = {}
        self.used_tx_hashes: set[str] = set()
        self.purchases: List[Dict[str, Any]] = []

        self._load_state()

    def _load_state(self) -> None:
        if not self.state_file or not os.path.exists(self.state_file):
            return
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.current_batch = int(data.get("current_batch", 1))
            raw_batches = data.get("batch_sold_voin", {})
            for b in range(1, TOTAL_BATCHES + 1):
                self.batch_sold_voin[b] = float(raw_batches.get(str(b), raw_batches.get(b, 0.0)))

            raw_spent = data.get("wallet_batch_spent_usd", {})
            for key_str, val in raw_spent.items():
                parts = key_str.split(":", 1)
                if len(parts) == 2:
                    self.wallet_batch_spent_usd[(parts[0].lower(), int(parts[1]))] = float(val)

            self.used_tx_hashes = {str(h).lower() for h in data.get("used_tx_hashes", [])}
            self.purchases = list(data.get("purchases", []))
            self._advance_batch_if_needed()
        except Exception:
            pass

    def _save_state(self) -> None:
        if not self.state_file:
            return
        payload = {
            "current_batch": self.current_batch,
            "batch_sold_voin": {str(k): v for k, v in self.batch_sold_voin.items()},
            "wallet_batch_spent_usd": {
                f"{wallet}:{batch_id}": amt
                for (wallet, batch_id), amt in self.wallet_batch_spent_usd.items()
            },
            "used_tx_hashes": sorted(self.used_tx_hashes),
            "purchases": self.purchases,
        }
        tmp_path = f"{self.state_file}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp_path, self.state_file)

    def _advance_batch_if_needed(self) -> None:
        while (
            self.current_batch < TOTAL_BATCHES
            and self.batch_sold_voin[self.current_batch] >= BATCH_VOIN_ALLOCATION
        ):
            self.current_batch += 1

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            self._advance_batch_if_needed()
            tokens_sold = sum(self.batch_sold_voin.values())
            total_presale_quota = BATCH_VOIN_ALLOCATION * TOTAL_BATCHES
            tokens_remaining = max(0.0, total_presale_quota - tokens_sold)
            return {
                "status": "success",
                "current_batch": self.current_batch,
                "tokens_sold": tokens_sold,
                "tokens_remaining": tokens_remaining,
                "batch_details": {str(k): v for k, v in self.batch_sold_voin.items()},
                "batch_prices_usd": {str(k): v for k, v in BATCH_PRICES_USD.items()},
                "min_purchase_usd": MIN_PURCHASE_USD_WEI / (10**18),
                "max_purchase_usd_per_batch": MAX_PURCHASE_USD_PER_BATCH_WEI / (10**18),
            }

    def get_wallet_history(self, wallet_address: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if not wallet_address:
                return list(reversed(self.purchases))
            norm = normalize_address(wallet_address)
            return [p for p in reversed(self.purchases) if p.get("wallet_address") == norm]

    def process_buy(self, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        wallet = normalize_address(payload.get("wallet_address"))
        if not wallet:
            return 400, {"status": "error", "reason": "Invalid wallet_address format (expected 0x... 42 chars)."}

        try:
            amount_paid = float(payload.get("amount_paid"))
        except (TypeError, ValueError):
            return 400, {"status": "error", "reason": "amount_paid must be a valid number."}

        min_usd = MIN_PURCHASE_USD_WEI / (10**18)
        max_usd = MAX_PURCHASE_USD_PER_BATCH_WEI / (10**18)
        if amount_paid < min_usd or amount_paid > max_usd:
            return 400, {
                "status": "error",
                "reason": f"amount_paid must be between ${min_usd:g} and ${max_usd:g} per wallet per batch.",
            }

        tx_hash = payload.get("tx_hash")
        if self.require_tx_hash and not tx_hash:
            return 400, {"status": "error", "reason": "tx_hash is required."}

        with self._lock:
            self._advance_batch_if_needed()
            batch_id = self.current_batch
            price_per_voin = BATCH_PRICES_USD.get(batch_id, 0.01)

            already_spent_usd = self.wallet_batch_spent_usd.get((wallet, batch_id), 0.0)
            if already_spent_usd + amount_paid > max_usd + 1e-9:
                return 400, {
                    "status": "error",
                    "reason": f"Purchase exceeds ${max_usd:g} max per wallet in Batch {batch_id}.",
                }

            verified_usd = amount_paid
            tokens_received = round(amount_paid / price_per_voin, 6)
            verified_batch = batch_id
            onchain_meta: Optional[Dict[str, Any]] = None

            if tx_hash:
                norm_tx = str(tx_hash).strip().lower()
                if norm_tx in self.used_tx_hashes:
                    return 409, {"status": "error", "reason": "Transaction hash has already been processed."}

                existing_spent_wei = int(round(already_spent_usd * (10**18)))
                ver = self.verifier.verify_presale_transaction(
                    tx_hash=norm_tx,
                    expected_buyer=wallet,
                    existing_batch_spent_usd_wei=existing_spent_wei,
                )
                if not ver.valid:
                    return 400, {
                        "status": "error",
                        "reason": ver.reason or "On-chain transaction verification failed.",
                    }

                if ver.batch_id is not None and 1 <= ver.batch_id <= TOTAL_BATCHES:
                    verified_batch = ver.batch_id
                    price_per_voin = BATCH_PRICES_USD.get(verified_batch, price_per_voin)

                if ver.usd_value_wei is not None and ver.usd_value_wei > 0:
                    verified_usd = ver.usd_value_wei / (10**18)

                if ver.voin_amount_wei is not None and ver.voin_amount_wei > 0:
                    tokens_received = round(ver.voin_amount_wei / (10**18), 6)
                else:
                    tokens_received = round(verified_usd / price_per_voin, 6)

                self.used_tx_hashes.add(norm_tx)
                onchain_meta = {
                    "tx_hash": ver.tx_hash,
                    "chain_id": ver.chain_id,
                    "block_number": ver.block_number,
                    "payment_token": ver.payment_token,
                }

            remaining_in_batch = BATCH_VOIN_ALLOCATION - self.batch_sold_voin[verified_batch]
            if tokens_received > remaining_in_batch + 1e-9:
                return 400, {
                    "status": "error",
                    "reason": f"Insufficient remaining quota in Batch {verified_batch}.",
                }

            self.batch_sold_voin[verified_batch] = round(
                self.batch_sold_voin[verified_batch] + tokens_received, 6
            )
            self.wallet_batch_spent_usd[(wallet, verified_batch)] = round(
                already_spent_usd + verified_usd, 6
            )
            self._advance_batch_if_needed()

            sales_rank = len(self.purchases) + 1
            record = {
                "sales_rank": sales_rank,
                "wallet_address": wallet,
                "batch": verified_batch,
                "price_per_voin_usd": price_per_voin,
                "amount_paid": verified_usd,
                "tokens_received": tokens_received,
                "timestamp": int(time.time()),
                "onchain": onchain_meta,
            }
            self.purchases.append(record)
            self._save_state()

            return 200, {
                "status": "success",
                "sales_rank": sales_rank,
                "batch": verified_batch,
                "price_per_voin_usd": price_per_voin,
                "amount_paid": verified_usd,
                "tokens_received": tokens_received,
                "voin_amount": tokens_received,
                "onchain": onchain_meta,
            }
