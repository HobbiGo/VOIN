#!/usr/bin/env python3
"""VOIN test-wallet helper. No key reads, saved passwords, retries, or auto-consent."""
import argparse
from pathlib import Path
import re
import subprocess
import sys

ADDRESS = re.compile(r"voin_[0-9a-f]{64}")
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}")
HASH = re.compile(r"[0-9a-fA-F]{64}")

def build(action, address=None, txhash=None, wallet=None, recipient=None, amount=None):
    if action == "balance":
        if not ADDRESS.fullmatch(address or ""):
            raise ValueError("Alamat harus voin_ diikuti 64 karakter hex kecil")
        return ["-action", "balance", "-address", address]
    if action == "status":
        if not HASH.fullmatch(txhash or ""):
            raise ValueError("Hash harus 64 karakter hex, tanpa awalan 0x")
        return ["-action", "status", "-hash", txhash]
    if action == "send":
        if not NAME.fullmatch(wallet or "") or not wallet.endswith(".enc"):
            raise ValueError("Gunakan basename wallet .enc, bukan path")
        if not ADDRESS.fullmatch(recipient or ""):
            raise ValueError("Alamat penerima tidak valid")
        if not isinstance(amount, int) or isinstance(amount, bool) or not 1 <= amount <= 2**64-1:
            raise ValueError("Jumlah harus bilangan bulat positif uint64")
        return ["-action", "send", "-wallet", wallet, "-to", recipient, "-amount", str(amount)]
    raise ValueError("Aksi tidak dikenal")

def selftest():
    import unittest
    class Tests(unittest.TestCase):
        def test_balance(self):
            a = "voin_" + "a"*64
            self.assertEqual(build("balance", address=a), ["-action", "balance", "-address", a])
        def test_status(self):
            self.assertEqual(build("status", txhash="b"*64)[-1], "b"*64)
        def test_send(self):
            args = build("send", wallet="test.enc", recipient="voin_"+"b"*64, amount=1)
            self.assertEqual(args, ["-action", "send", "-wallet", "test.enc", "-to", "voin_"+"b"*64, "-amount", "1"])
            self.assertNotIn("KIRIM", args)
        def test_bad_names(self):
            for name in ("../test.enc", "/tmp/test.enc", "x.json", "a;echo.enc", ""):
                with self.assertRaises(ValueError):
                    build("send", wallet=name, recipient="voin_"+"a"*64, amount=1)
        def test_bad_amounts(self):
            for n in (0, -1, 2**64, True, "1"):
                with self.assertRaises(ValueError):
                    build("send", wallet="test.enc", recipient="voin_"+"a"*64, amount=n)
        def test_bad_public_inputs(self):
            for a in ("", "voin_short", "voin_"+"g"*64):
                with self.assertRaises(ValueError): build("balance", address=a)
            with self.assertRaises(ValueError): build("status", txhash="not-a-hash")
    result = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    print("SELFTEST: hanya menyusun argumen; tidak memanggil wallet atau RPC.")
    return 0 if result.wasSuccessful() else 1

def main():
    parser = argparse.ArgumentParser(description="VOIN TEST wallet helper. Bukan wallet produksi. Passphrase tetap di prompt signer; KIRIM bukan 2FA.")
    subs = parser.add_subparsers(dest="action", required=True)
    subs.add_parser("selftest", help="Tes lokal tanpa wallet atau RPC")
    b = subs.add_parser("balance", help="Saldo publik, tidak menandatangani")
    b.add_argument("address")
    s = subs.add_parser("status", help="Status transaksi publik, tidak menandatangani")
    s.add_argument("hash")
    t = subs.add_parser("send", help="TRANSFER DEVNET; memerlukan terminal dan persetujuan signer")
    t.add_argument("wallet", help="Nama file .enc dalam ~/voin-encrypted-test-wallets")
    t.add_argument("recipient")
    t.add_argument("amount", type=int, help="Bilangan bulat unit uji")
    args = parser.parse_args()
    if args.action == "selftest": return selftest()
    command = build(args.action, address=getattr(args, "address", None), txhash=getattr(args, "hash", None), wallet=getattr(args, "wallet", None), recipient=getattr(args, "recipient", None), amount=getattr(args, "amount", None))
    binary = Path.home()/"voin-tools/bin/voin-encrypted-wallet"
    if not binary.is_file(): raise ValueError("Binary signer tidak ditemukan; tidak melakukan build otomatis")
    if args.action == "send":
        if not sys.stdin.isatty(): raise ValueError("Transfer harus dari terminal interaktif")
        print("TRANSFER UNIT UJI. Pastikan binary/devnet yang digunakan benar dan dipercaya.", flush=True)
        print("Signer menampilkan jaringan/penerima/jumlah/nonce sebelum meminta KIRIM.", flush=True)
        print("Passphrase hanya pada prompt tersembunyi signer. Tidak ada percobaan ulang otomatis.", flush=True)
    try:
        return subprocess.run([str(binary), *command], check=False).returncode
    except KeyboardInterrupt:
        print("\nDihentikan. Jika transaksi sudah dikirim, cek hash sebelum mencoba lagi.", file=sys.stderr)
        return 130

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError) as exc:
        print("STOP:", exc, file=sys.stderr)
        sys.exit(2)
