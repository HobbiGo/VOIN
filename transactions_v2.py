"""Experimental VOIN transaction rules, version 2."""
import hashlib
import json
import re

CHAIN_ID = "voin-devnet-1"
DOMAIN = b"VOIN:transaction:v2\x00"
MAX_VALUE = (1 << 64) - 1
ADDRESS = re.compile(r"voin_[0-9a-f]{64}")


def address(public_key):
    return "voin_" + hashlib.sha256(public_key).hexdigest()


def transaction_bytes(tx, expected_chain_id=CHAIN_ID):
    fields = {
        "chain_id", "sender", "recipient", "amount", "nonce"
    }
    if not isinstance(tx, dict) or set(tx) != fields:
        raise ValueError("Invalid transaction fields")
    if tx["chain_id"] != expected_chain_id:
        raise ValueError("Wrong network")
    for name in ("sender", "recipient"):
        value = tx[name]
        if not isinstance(value, str) or not ADDRESS.fullmatch(value):
            raise ValueError("Invalid address")
    if tx["sender"] == tx["recipient"]:
        raise ValueError("Sender and recipient must differ")
    for name in ("amount", "nonce"):
        value = tx[name]
        if type(value) is not int or not 1 <= value <= MAX_VALUE:
            raise ValueError("Invalid amount or nonce")
    return DOMAIN + json.dumps(
        tx, sort_keys=True, separators=(",", ":"),
        allow_nan=False
    ).encode("utf-8")

from pqcrypto.sign import ml_dsa_44 as crypto


def check_public_key(public_key):
    if not isinstance(public_key, bytes):
        raise ValueError("Public key must be bytes")
    if len(public_key) != crypto.PUBLIC_KEY_SIZE:
        raise ValueError("Invalid public key size")


def sign_transaction(tx, public_key, secret_key):
    message = transaction_bytes(tx)
    check_public_key(public_key)
    if tx["sender"] != address(public_key):
        raise ValueError("Sender does not match public key")
    signature = crypto.sign(secret_key, message)
    crypto.verify(public_key, message, signature)
    return signature


def verify_transaction(tx, public_key, signature):
    message = transaction_bytes(tx)
    check_public_key(public_key)
    if tx["sender"] != address(public_key):
        raise ValueError("Sender does not match public key")
    if not isinstance(signature, bytes):
        raise ValueError("Signature must be bytes")
    if len(signature) != crypto.SIGNATURE_SIZE:
        raise ValueError("Invalid signature size")
    crypto.verify(public_key, message, signature)
    return True
