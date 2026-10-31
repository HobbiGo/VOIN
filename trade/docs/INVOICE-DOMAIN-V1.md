# VOIN invoice domain: isolated first implementation

Status: experimental domain library; not an API, payment service, database, or on-chain invoice protocol.
No RPC, private-key access, conversion, stablecoin, or transaction sending.

Files:
- invoice_model.py: immutable values, invoice transitions, bounded unverified pointers.
- test_invoice_model.py: synthetic local tests, run only when explicitly requested.

Amount is an integer in explicit minor units. Currency syntax checking is NOT a registry
of supported currencies and does not certify a currency's scale. A later trusted asset/
currency registry must constrain accepted currency+scale pairs. Invoice money is NOT
assumed equal to VOIN units. No exchange-rate or settlement accounting is implemented.

A payment candidate is only an untrusted (chain_id, hash) pointer. It does not mark the
invoice paid, calculate an outstanding amount, or prove a transfer. Retain pointers for
late/cancelled invoices for review. Deduplication here is only within one in-memory
invoice. Global uniqueness and transactional allocation require storage/verification later.

Future adapter must verify actual chain, execution, recipient, asset, amount and finality.
No caller-provided verified=True option exists. Partial payment, overpayment, quote locks,
refund execution and reconciliation remain unimplemented.

Objects are immutable for ordinary application use, NOT tamper-proof or authorization.
Host application must authenticate/authorize calls, validate imported records, use a trusted
clock, protect identifiers, rate-limit and persist atomically. No arbitrary user object should
be treated as verified domain state. No PII should be used as buyer/seller references.

Status lifecycle and payment status are separate. No event store/audit history yet.
No claim of legal invoice validity, compliance, production readiness, or security audit.

Optional isolated tests (no external connection):
    python trade/domain/test_invoice_model.py

A passing test suite only covers its cases. Scaffold/installation does not run tests.
