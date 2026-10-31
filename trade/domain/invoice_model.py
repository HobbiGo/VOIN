"""Experimental invoice domain. No network, persistence, settlement, or legal claims."""
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
