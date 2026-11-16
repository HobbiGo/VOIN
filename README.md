# VOIN — Native Layer 1 Blockchain

**Quantum-resistant Layer 1 with native VOIN coin (260,000,000 supply), modular security, and Web4 vision.**

VOIN is an independent blockchain technology initiative building a modular Layer 1 network from the ground up. The long-term target is a self-sovereign chain with its own native coin, ML-DSA (FIPS 204) post-quantum signatures, distributed consensus, peer-to-peer networking, and a Web4 application layer.

> **Status: Early development.** This repository currently contains a local ledger prototype, experimental wallet identity/verification modules, and ML-DSA security research. **No mainnet. No native coin in circulation. No production consensus.** See the Roadmap section below for the path to devnet and mainnet.

---

## Vision

VOIN will become an independent Layer 1 blockchain with:

- **Native coin:** VOIN, total supply **260,000,000 VOIN**
- **Primary signature scheme:** ML-DSA (FIPS 204), with hybrid ECDSA + ML-DSA during transition
- **Modular architecture:** consensus, P2P network, state layer, and execution layer as separate modules
- **Wallet identity & verification engine** with cryptographic ownership proof
- **Web4 / AI integration** (long-term vision, not current scope)

---

## Current Status

| Component | Status |
|---|---|
| VOIN Core (local ledger prototype) | Experimental |
| Identity Engine | Initial implementation |
| Wallet Verification Engine | Initial implementation |
| Security Engine (signature, challenge, nonce) | Created, pending integration |
| ML-DSA (post-quantum) research | In progress |
| Network Engine (P2P) | Planned |
| Consensus Engine | Planned |
| Native VOIN L1 | **Not deployed** |
| Native coin (260M VOIN) | **Not minted / not in circulation** |

**What works today:** `python voin.py` runs a local ledger simulator with SHA-256 block hashing, block linking, basic Proof of Work, balance validation, transaction nonce checking, and ledger consistency validation. Tests run via `python -m unittest discover -s tests -v`.

**What does not exist yet:** distributed consensus, peer-to-peer communication, production transaction authorization, native coin operations, and any deployed network.

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Python 3.10+ | Core ledger and node development |
| ML-DSA (FIPS 204) | Post-quantum signature scheme (primary target) |
| ECDSA (eth-account) | Transitional/hybrid signature support |
| SHA-256 | Ledger hashing |
| SQLite / Cloudflare D1 | Planned persistent storage |
| Cloudflare Workers | Planned lightweight services (signature verification, RPC endpoints) |
| GitHub Actions | CI / automated testing |

**Note on Cloudflare ML-DSA:** Cloudflare Workers supports ML-DSA-44/65/87 via the Web Crypto API since October 2026, enabled with the `webcrypto_modern_algorithms` compatibility flag. This support is experimental and subject to change. VOIN will use it for lightweight verification services, while the Python node uses a separate ML-DSA library for ledger-level verification.

---

## Native Coin Specification

- **Name:** VOIN
- **Total supply:** 260,000,000 VOIN
- **Distribution:** To be defined before devnet
- **Status:** Not yet minted. No token contract. No circulation.
- **Consensus role:** To be defined (validator rewards, staking, or fee model) before devnet.

---

## Security Principles

- Private keys must remain under user control.
- Wallet ownership must be cryptographically verified.
- Transactions must require valid authorization.
- Nonces must prevent transaction replay.
- Identity and transaction authentication must be separated.
- ML-DSA signatures are larger (2.4 KB+ for ML-DSA-44) and costlier to verify than ECDSA; this affects transaction size and network bandwidth.
- Security components must be independently tested.
- **Production deployment requires third-party security review and audit.**

---

## Installation & Running (Prototype)

Requirements: Python 3.10+, pip, Git.

```bash
pip install -r requirements.txt
python voin.py                          # run local ledger prototype
python -m unittest discover -s tests -v # run tests
