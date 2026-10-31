#!/usr/bin/env python3
"""Create isolated VOIN invoice domain code, tests, and documentation.
Preview by default; --apply creates missing files, never overwrites.
No RPC, database, wallet, transfers, dependencies, node changes, commit or push.
"""
import argparse
from pathlib import Path
import subprocess

MODEL = r'''"""Experimental invoice domain. No network, persistence, settlement, or legal claims."""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
import re

MAX_MINOR = 2**63 - 1
REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
CHAIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

class DomainError(ValueError):
    pass

class InvoiceStatus(str, Enum):
    DRAFT = "draft"
    ISSUED = "issued"
    CANCELLED = "cancelled"
    EXPIRED = "expired"

def reference(value, label):
    if not isinstance(value, str) or not REF.fullmatch(value):
        raise DomainError(label + " must be an opaque reference of 1-64 ASCII characters")

def instant(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise DomainError("Explicit timezone-aware datetime required")
    return value.astimezone(timezone.utc)

@dataclass(frozen=True)
class InvoiceAmount:
    currency: str
    minor_units: int
    scale: int

    def __post_init__(self):
        if not isinstance(self.currency, str) or not re.fullmatch(r"[A-Z]{3}", self.currency):
            raise DomainError("Invoice currency syntax requires 3 uppercase ASCII letters")
        if type(self.minor_units) is not int or not 1 <= self.minor_units <= MAX_MINOR:
            raise DomainError("Positive bounded integer minor units required; no floats or bool")
        if type(self.scale) is not int or not 0 <= self.scale <= 8:
            raise DomainError("Explicit scale must be an integer 0-8")

@dataclass(frozen=True)
class PaymentCandidate:
    chain_id: str
    tx_hash: str
    # Deliberately no amount, verified flag, or ability to mark an invoice paid.
    # These are untrusted pointers, not settlement evidence.
    def __post_init__(self):
        if not isinstance(self.chain_id, str) or not CHAIN.fullmatch(self.chain_id):
            raise DomainError("Invalid chain identifier")
        if not isinstance(self.tx_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", self.tx_hash):
            raise DomainError("Transaction hash must be 64 hex characters without 0x")
        object.__setattr__(self, "tx_hash", self.tx_hash.lower())

@dataclass(frozen=True)
class Invoice:
    invoice_id: str
    buyer_ref: str
    seller_ref: str
    amount: InvoiceAmount
    created_at: datetime
    due_at: datetime
    status: InvoiceStatus = InvoiceStatus.DRAFT
    issued_at: datetime | None = None
    candidates: tuple[PaymentCandidate, ...] = ()

    def __post_init__(self):
        for label in ("invoice_id", "buyer_ref", "seller_ref"):
            reference(getattr(self, label), label)
        if self.buyer_ref == self.seller_ref:
            raise DomainError("Buyer and seller references must differ")
        if not isinstance(self.amount, InvoiceAmount):
            raise DomainError("Validated InvoiceAmount required")
        if type(self.status) is not InvoiceStatus:
            raise DomainError("InvoiceStatus enum required")
        created, due = instant(self.created_at), instant(self.due_at)
        if due <= created:
            raise DomainError("Due time must follow creation time")
        object.__setattr__(self, "created_at", created)
        object.__setattr__(self, "due_at", due)
        if self.issued_at is not None:
            issued = instant(self.issued_at)
            if not created <= issued < due:
                raise DomainError("Issue time must be within invoice validity")
            object.__setattr__(self, "issued_at", issued)
        if self.status in (InvoiceStatus.ISSUED, InvoiceStatus.EXPIRED) and self.issued_at is None:
            raise DomainError("Issued or expired invoice requires issue time")
        if self.status is InvoiceStatus.DRAFT and self.issued_at is not None:
            raise DomainError("Draft cannot have issue time")
        if type(self.candidates) is not tuple or len(self.candidates) > 100:
            raise DomainError("Candidate tuple limited to 100")
        if any(type(c) is not PaymentCandidate for c in self.candidates):
            raise DomainError("Invalid candidate")
        if len({(c.chain_id, c.tx_hash) for c in self.candidates}) != len(self.candidates):
            raise DomainError("Duplicate candidate in invoice")
        if self.status is InvoiceStatus.DRAFT and self.candidates:
            raise DomainError("Draft cannot have payment candidates")
        if self.candidates and self.issued_at is None:
            raise DomainError("Payment candidate requires an invoice that was issued")

    def issue(self, now):
        now = instant(now)
        if self.status is not InvoiceStatus.DRAFT or not self.created_at <= now < self.due_at:
            raise DomainError("Only a valid draft can be issued")
        return replace(self, status=InvoiceStatus.ISSUED, issued_at=now)

    def cancel(self, now):
        now = instant(now)
        if now < self.created_at or (self.issued_at is not None and now < self.issued_at):
            raise DomainError("Cancellation time precedes invoice activity")
        if self.status not in (InvoiceStatus.DRAFT, InvoiceStatus.ISSUED):
            raise DomainError("Invoice is not cancellable")
        if self.status is InvoiceStatus.ISSUED and now >= self.due_at:
            raise DomainError("Use expire for overdue issued invoice")
        # Cancellation NEVER removes candidates or refunds funds.
        return replace(self, status=InvoiceStatus.CANCELLED)

    def expire(self, now):
        now = instant(now)
        if self.status is not InvoiceStatus.ISSUED or now < self.due_at:
            raise DomainError("Only an overdue issued invoice can expire")
        return replace(self, status=InvoiceStatus.EXPIRED)

    def note_candidate(self, candidate):
        if type(candidate) is not PaymentCandidate:
            raise DomainError("Validated candidate required")
        if self.issued_at is None:
            raise DomainError("Invoice must have been issued")
        # Late/cancelled invoice pointers are retained for later review, not silently lost.
        if candidate in self.candidates:
            return self
        if len(self.candidates) >= 100:
            raise DomainError("Candidate capacity reached")
        return replace(self, candidates=self.candidates + (candidate,))

    def public_summary(self):
        # Party references excluded here; they still must be protected by the host application.
        return {"invoice_id": self.invoice_id, "invoice_status": self.status.value,
                "currency": self.amount.currency, "amount_minor": self.amount.minor_units,
                "scale": self.amount.scale, "candidate_count": len(self.candidates),
                "payment_status": "unverified" if self.candidates else "not_assessed"}
'''

TESTS = r'''"""Isolated synthetic unit tests: no RPC, wallet files, database, or transfers."""
import importlib.util
from pathlib import Path
import sys
import unittest
from datetime import datetime, timedelta, timezone
from dataclasses import FrozenInstanceError

path = Path(__file__).with_name("invoice_model.py")
spec = importlib.util.spec_from_file_location("voin_invoice_domain_under_test", path)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)

class InvoiceTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2030, 1, 1, tzinfo=timezone.utc)
        self.inv = m.Invoice("inv_1", "buyer_1", "seller_1", m.InvoiceAmount("USD", 10000, 2), self.now, self.now+timedelta(days=1))
        self.candidate = m.PaymentCandidate("voin-devnet-1", "A"*64)
    def test_immutable(self):
        with self.assertRaises(FrozenInstanceError): self.inv.status = m.InvoiceStatus.ISSUED
    def test_amount_rejection(self):
        for value in (0, -1, True, 1.0, "100", 2**63):
            with self.assertRaises(m.DomainError): m.InvoiceAmount("USD", value, 2)
        for scale in (-1, True, 9):
            with self.assertRaises(m.DomainError): m.InvoiceAmount("USD", 100, scale)
        with self.assertRaises(m.DomainError): m.InvoiceAmount("usd", 100, 2)
    def test_issue_and_no_reissue(self):
        inv = self.inv.issue(self.now)
        self.assertEqual(inv.status, m.InvoiceStatus.ISSUED)
        self.assertEqual(self.inv.status, m.InvoiceStatus.DRAFT)
        with self.assertRaises(m.DomainError): inv.issue(self.now)
    def test_due_boundary(self):
        with self.assertRaises(m.DomainError): self.inv.issue(self.inv.due_at)
        inv = self.inv.issue(self.now)
        with self.assertRaises(m.DomainError): inv.expire(self.now)
        self.assertEqual(inv.expire(inv.due_at).status, m.InvoiceStatus.EXPIRED)
    def test_timezone_required(self):
        with self.assertRaises(m.DomainError): self.inv.issue(datetime(2030,1,1))
    def test_cancel_terminal(self):
        inv = self.inv.cancel(self.now)
        with self.assertRaises(m.DomainError): inv.issue(self.now)
        with self.assertRaises(m.DomainError): inv.cancel(self.now)
    def test_candidate_not_payment(self):
        inv = self.inv.issue(self.now).note_candidate(self.candidate)
        self.assertEqual(inv.public_summary()["payment_status"], "unverified")
        self.assertEqual(inv.status, m.InvoiceStatus.ISSUED)
        self.assertFalse(hasattr(inv, "mark_paid"))
        with self.assertRaises(m.DomainError): self.inv.note_candidate(self.candidate)
    def test_idempotent_pointer(self):
        inv = self.inv.issue(self.now).note_candidate(self.candidate)
        self.assertIs(inv.note_candidate(m.PaymentCandidate("voin-devnet-1", "a"*64)), inv)
    def test_late_pointer_retained(self):
        inv = self.inv.issue(self.now).expire(self.inv.due_at).note_candidate(self.candidate)
        self.assertEqual(inv.status, m.InvoiceStatus.EXPIRED)
        self.assertEqual(inv.public_summary()["payment_status"], "unverified")
    def test_validation_and_limits(self):
        with self.assertRaises(m.DomainError): m.PaymentCandidate("voin-devnet-1", "0x"+"a"*64)
        with self.assertRaises(m.DomainError): m.PaymentCandidate("bad chain", "a"*64)
        inv = self.inv.issue(self.now)
        for i in range(100): inv = inv.note_candidate(m.PaymentCandidate("voin-devnet-1", f"{i:064x}"))
        with self.assertRaises(m.DomainError): inv.note_candidate(m.PaymentCandidate("voin-devnet-1", f"{100:064x}"))
    def test_distinct_parties_and_reference(self):
        with self.assertRaises(m.DomainError): m.Invoice("../x", "buyer", "seller", self.inv.amount, self.now, self.inv.due_at)
        with self.assertRaises(m.DomainError): m.Invoice("x", "same", "same", self.inv.amount, self.now, self.inv.due_at)
    def test_summary_omits_parties(self):
        self.assertNotIn("buyer_ref", self.inv.public_summary())
        self.assertNotIn("seller_ref", self.inv.public_summary())

if __name__ == "__main__": unittest.main()
'''

README = '''# VOIN invoice domain: isolated first implementation

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
'''

CONTENTS = {
    'trade/domain/invoice_model.py': MODEL,
    'trade/domain/test_invoice_model.py': TESTS,
    'trade/docs/INVOICE-DOMAIN-V1.md': README,
}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args=parser.parse_args()
    root=Path(subprocess.check_output(['git','rev-parse','--show-toplevel'],text=True).strip()).resolve()
    if not (root/'consensus/voin-app/go.mod').is_file(): raise ValueError('VOIN repository not found')
    if not (root/'trade/domain/invoices/VOIN-SCOPE.md').is_file(): raise ValueError('Expected trade scaffold not found')
    # Syntax inspection only, not execution or unit testing.
    for name,text in CONTENTS.items():
        if name.endswith('.py'): compile(text,name,'exec')
    for name,text in CONTENTS.items():
        target=root/name
        if target.is_symlink(): raise ValueError('Symlink refused: '+name)
        for parent in target.parents:
            if parent==root: break
            if parent.is_symlink(): raise ValueError('Symlink parent refused: '+name)
        if target.exists() and (not target.is_file() or target.read_text()!=text):
            raise ValueError('Existing destination differs; nothing written: '+name)
    count=0
    for name,text in CONTENTS.items():
        target=root/name
        if target.exists(): print('KEEP:',name); continue
        if args.apply:
            target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('x') as f: f.write(text)
        count+=1
        print('CREATED:' if args.apply else 'PLAN:',name)
    print(('APPLIED' if args.apply else 'PREVIEW')+':',count,'new files. Python syntax checked; unit tests NOT run.')
    print('No RPC, database, wallet, node changes, transactions, dependencies, commit or push.')
    print('Candidate hash is NOT verified payment. No real funds or production use.')

if __name__=='__main__':
    try: main()
    except Exception as exc:
        print('STOP:',exc)
        print('Partial new files may remain after write failure; existing files are not intentionally overwritten.')
        raise SystemExit(1)
