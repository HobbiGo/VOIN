from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


DEFAULT_TREASURY_ADDRESS = "0xAEb22359588A50e6F746004E66418Eb2c978dAA2"
DEFAULT_RPC_URL = os.getenv("BSC_RPC_URL", "https://bsc-dataseed.binance.org/")

# Jadwal presale: 1 Desember 2026 00:00:00 UTC s/d 31 Desember 2028 23:59:59 UTC
PRESALE_START_TIMESTAMP = 1796083200
PRESALE_END_TIMESTAMP = 1861919999

# Batas pembelian per wallet per batch (skala 1e18 USD)
MIN_PURCHASE_USD_WEI = 25 * (10**18)
MAX_PURCHASE_USD_PER_BATCH_WEI = 10_000 * (10**18)
TOTAL_BATCHES = 10

# Keccak-256 topic0 untuk event:
# TokensPurchased(address,address,uint256,uint256,uint256,uint256,uint256)
TOKENS_PURCHASED_TOPIC0 = (os.getenv("VOIN_TOKENS_PURCHASED_TOPIC0") or "").strip()


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
        expected_chain_id: Optional[int] = 56,
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
        if not (1 <= batch_id <= TOTAL_BATCHES):
            return None

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
