# Experimental signed-transfer ABCI integration

TransferApp is a separate, explicitly selected application mode.
The original App and running empty-block server are unchanged.

Implemented:
- ML-DSA-44 signed transfers with strict canonical JSON.
- Network binding and public-key-derived sender addresses.
- Balance, sequential nonce, replay, and overflow checks.
- Sequential proposal selection and proposal validation.
- Pending-state finalization followed by persistent commit.
- Restoration of committed balances and replay protection.

Local tests cover these application paths.
Limits: 100 candidates per prepared proposal, 100 transactions
per accepted block, and 1 MiB of transaction data per block.
These are prototype limits, not measured throughput.

Not yet demonstrated:
- Transfer submission through a running CometBFT node.
- Transfer-server restart or multi-validator transfer consensus.
- Production concurrency, crash recovery, or independent audit.

The Go transfer format is not wire-compatible with the Python prototype.
No real funds, private keys, or runtime data belong in this repository.
