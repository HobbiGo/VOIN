"""Local prototype snapshots, not a production database."""
import json
import os
import tempfile
from pathlib import Path

MAX_BYTES = 10 * 1024 * 1024


def save_ledger(ledger, filename):
    ledger.validate()
    document = {
        "format": "voin-snapshot-v1",
        "chain": ledger.chain,
    }
    data = json.dumps(
        document, sort_keys=True,
        separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    if len(data) > MAX_BYTES:
        raise ValueError("Snapshot too large")

    path = Path(filename)
    fd, temporary = tempfile.mkstemp(
        prefix=".voin-", dir=path.parent
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("Invalid JSON constant")


def load_ledger(filename, allocations, difficulty=2):
    from strict_chain import StrictVoinChain

    with open(filename, "rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Snapshot too large")

    document = json.loads(
        data,
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
    if not isinstance(document, dict) or set(document) != {
        "format", "chain"
    }:
        raise ValueError("Invalid snapshot fields")
    if document["format"] != "voin-snapshot-v1":
        raise ValueError("Unsupported snapshot format")

    ledger = StrictVoinChain(allocations, difficulty)
    ledger.chain = document["chain"]
    ledger.validate()
    return ledger
