# VOIN local ABCI integration experiment

Date: 2026-10-31
CometBFT: 1.0.1
Application: VOIN Go ABCI scaffold
Network: voin-devnet-1
Topology: one local validator, not a decentralized deployment
ABCI/RPC/P2P: localhost only

Observed:
- Empty blocks were finalized and committed by the VOIN application.
- Node, application, and state file advanced from height 31 to 36.
- A submitted test transaction returned application code 1 with:
  VOIN transaction processing is not enabled
- CometBFT exposed this rejection through an HTTP 500 RPC error.
- A saved state file hash matched the app_hash in the following block.

Limits:
- Transfers and ML-DSA are not integrated into the Go application.
- The genesis allocation uses a dummy test address.
- Live server restart with CometBFT has not been tested.
- No malicious-validator, crash-durability, or performance guarantee.
- Runtime data and validator keys must remain outside this repository.
