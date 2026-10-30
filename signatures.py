"""Experimental transaction signatures, not yet enforced by VoinChain."""
import hashlib
import json
from pqcrypto.sign.ml_dsa_44 import keygen, sign, verify

DOMAIN = b"VOIN:transaction:v1\x00"


def address(public_key):
    return "voin_" + hashlib.sha256(public_key).hexdigest()


def transaction_bytes(tx):
    if not isinstance(tx, dict):
        raise ValueError("Transaction must be a dictionary")
    if set(tx) != {"sender", "recipient", "amount", "nonce"}:
        raise ValueError("Invalid transaction fields")
    for field in ("sender", "recipient"):
        if not isinstance(tx[field], str) or not tx[field].strip():
            raise ValueError("Invalid account")
    for field in ("amount", "nonce"):
        if type(tx[field]) is not int or tx[field] <= 0:
            raise ValueError("Amount and nonce must be positive integers")
    return DOMAIN + json.dumps(
        tx, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def sign_transaction(tx, public_key, secret_key):
    if tx["sender"] != address(public_key):
        raise ValueError("Sender does not match public key")
    message = transaction_bytes(tx)
    signature = sign(secret_key, message)
    verify(public_key, message, signature)
    return signature


def verify_transaction(tx, public_key, signature):
    if tx["sender"] != address(public_key):
        raise ValueError("Sender does not match public key")
    verify(public_key, transaction_bytes(tx), signature)
    return True
