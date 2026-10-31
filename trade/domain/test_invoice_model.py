"""Isolated synthetic unit tests: no RPC, wallet files, database, or transfers."""
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
