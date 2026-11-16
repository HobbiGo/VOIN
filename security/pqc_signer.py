"""
VOIN Post-Quantum Signer (ML-DSA / FIPS 204)

Modul satu file untuk pembuatan kunci (key generation), penandatanganan (signing), 
dan verifikasi (verification) menggunakan ML-DSA.
Backend: dilithium-py (pure Python, untuk tahap edukasi/pengembangan).
Untuk produksi: ganti backend ke liboqs-python (C-backed).
"""

from __future__ import annotations

import os
from typing import Tuple

# --- Pemilihan Backend -------------------------------------------------------
# Menggunakan pure-Python dilithium-py untuk kemudahan development.
try:
    from dilithium_py.ml_dsa import ML_DSA_44 as _ML_DSA
    _BACKEND = "dilithium-py"
except ImportError as exc:
    raise ImportError(
        "Backend ML-DSA tidak ditemukan. Install dengan: pip install dilithium-py"
    ) from exc

# Ukuran parameter set (FIPS 204, ML-DSA-44)
_PK_SIZE = 1312
_SK_SIZE = 2560
_SIG_SIZE = 2420


def generate_keypair() -> Tuple[bytes, bytes]:
    """Menghasilkan pasangan kunci ML-DSA-44.

    Returns:
        (public_key, private_key) dalam format bytes mentah.
    """
    public_key, private_key = _ML_DSA.keygen()
    return bytes(public_key), bytes(private_key)


def sign(message: bytes, private_key: bytes) -> bytes:
    """Menandatangani pesan dengan ML-DSA-44.

    Args:
        message: pesan berupa bytes.
        private_key: private key bytes mentah.

    Returns:
        signature dalam format bytes mentah.
    """
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message harus berupa bytes")
    if len(private_key) != _SK_SIZE:
        raise ValueError(f"private_key harus {_SK_SIZE} bytes, tapi mendapat {len(private_key)}")
    
    signature = _ML_DSA.sign(bytes(private_key), bytes(message))
    return bytes(signature)


def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Memverifikasi signature ML-DSA-44.

    Returns:
        True jika valid, False jika tidak.
    """
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message harus berupa bytes")
    if len(public_key) != _PK_SIZE:
        raise ValueError(f"public_key harus {_PK_SIZE} bytes, tapi mendapat {len(public_key)}")
    if len(signature) != _SIG_SIZE:
        raise ValueError(f"signature harus {_SIG_SIZE} bytes, tapi mendapat {len(signature)}")
    
    try:
        return bool(_ML_DSA.verify(bytes(public_key), bytes(message), bytes(signature)))
    except Exception:
        return False


def verify_hex(message: bytes, signature_hex: str, public_key_hex: str) -> bool:
    """Helper untuk memverifikasi signature yang disimpan dalam format string hex.
    Digunakan oleh ledger voin.py.
    """
    try:
        signature = bytes.fromhex(signature_hex)
        public_key = bytes.fromhex(public_key_hex)
        return verify(message, signature, public_key)
    except (ValueError, TypeError):
        # Gagal konversi hex atau input tidak valid
        return False


def describe() -> dict:
    """Mengembalikan metadata tentang parameter set dan backend saat ini."""
    return {
        "algorithm": "ML-DSA-44",
        "standard": "FIPS 204",
        "backend": _BACKEND,
        "public_key_bytes": _PK_SIZE,
        "private_key_bytes": _SK_SIZE,
        "signature_bytes": _SIG_SIZE,
        "experimental": True,
        "production_ready": False,
    }


# --- Uji Mandiri (Self-test) -------------------------------------------------
if __name__ == "__main__":
    print("VOIN PQC signer self-test")
    print(describe())

    # 1. Generate Key
    pk, sk = generate_keypair()
    msg = os.urandom(32)

    # 2. Tanda Tangan
    sig = sign(msg, sk)
    ok = verify(msg, sig, pk)
    print(f"Valid signature verified: {ok}")
    assert ok, "Valid signature must verify"

    # 3. Uji Pesan yang Diubah
    tampered = bytearray(msg)
    tampered[0] ^= 0xFF
    bad = verify(bytes(tampered), sig, pk)
    print(f"Tampered message rejected: {not bad}")
    assert not bad, "Tampered message must not verify"

    print("OK (Semua tes berhasil)")
