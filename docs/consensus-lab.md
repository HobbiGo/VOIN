# Local consensus experiment

Date: 2026-10-31
Engine: CometBFT 1.0.1
Application: built-in kvstore, NOT the VOIN ledger
Environment: four processes in one Codespaces machine
Validator voting power: 1 each
P2P and RPC configured on localhost with separate ports

Observed:
- All four nodes returned the same block hash at height 65.
- With node3 stopped, node0–2 advanced from height 127 to 132.
- After node3 restarted, all four returned the same hash at height 168.

Limits:
- No VOIN transfers or ML-DSA integration tested in this network.
- No malicious-validator, partition, load, or production security test.
- One operator and machine, not operational decentralization.
- kvstore used here is not a production asset ledger.
- Runtime files and validator keys remain outside this repository.
- Never commit private validator keys or copy a live validator identity.

Additional observation:
- A unique key=value transaction was submitted through node0.
- The value consensus-test was subsequently read from all four nodes.
- This tests the example kvstore application, not VOIN coin transfers.
- Restart recovery after this application write has not been tested.
