import requests
import json
import sys
from eth_account import Account
from eth_account.messages import encode_defunct
from security.pqc_signer import generate_keypair, sign as pqc_sign
from voin import canonical_tx_message, canonical_block_message

def send_voin(node_url, sender_sk_evm, sender_sk_pqc, validator_sk_evm, validator_sk_pqc, recipient, amount, nonce):
    # 1. Setup Akun Pengirim
    sender_acct = Account.from_key(sender_sk_evm)
    
    # 2. Setup Akun Validator (Di L1 nyata, ini ada di server. Di sini kita simulasikan)
    validator_acct = Account.from_key(validator_sk_evm)

    # 3. Buat Transaksi
    tx = {"sender": sender_acct.address, "recipient": recipient, "amount": amount, "nonce": nonce}
    msg = canonical_tx_message(tx)
    
    # 4. Tanda tangan transaksi (Hybrid)
    tx_sig_ecdsa = sender_acct.sign_message(encode_defunct(primitive=msg)).signature.hex()
    tx_sig_mldsa = pqc_sign(msg, sender_sk_pqc).hex()

    # 5. Siapkan Block (Karena di API kita butuh signature validator blok)
    # Kita buat block dummy sesuai state node (asumsi block kosong selain genesis)
    # Di produksi, ini dilakukan oleh Node, bukan Wallet.
    payload = {
        "tx": tx,
        "sig_ecdsa": tx_sig_ecdsa,
        "sig_mldsa": tx_sig_mldsa,
        "validator_id": validator_acct.address
    }

    # Karena API node kita membutuhkan signature validator, kita buat di sini untuk simulasi
    # (Catatan: Di masa depan, endpoint /transaction seharusnya tidak butuh validator_sig dari wallet)
    # Untuk saat ini, kita butuh endpoint khusus dari node untuk menandatangani blok.
    # Mari kita modifikasi sedikit alurnya: Kirim tx mentah, biarkan Node yang membuat blok.
    
    # KIRIM KE NODE
    print(f"Mengirim {amount} VOIN ke {recipient}...")
    try:
        # (Karena keterbatasan API node kita yang mengharuskan validator_sig di payload, 
        # kita gunakan trik simulasi di mana wallet bertindak sebagai validator sementara)
        # Ini akan diperbaiki di fase Mainnet.
        
        # 1. Minta Node menyiapkan block (kita tambahkan endpoint /prepare di node nanti)
        # Untuk sekarang, kita asumsikan Node menerima transaksi mentah dan memprosesnya.
        
        res = requests.post(f"{node_url}/transaction", json=payload)
        print(f"Status: {res.status_code}")
        print(f"Respons: {res.json()}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Contoh penggunaan (Wallet Alice mengirim ke Bob)
    # CATATAN: Karena sistem kita sangat ketat, wallet harus tahu private key validator untuk simulasi ini.
    print("Ini adalah file kerangka CLI Wallet.")
    print("Penggunaan sesungguhnya akan diintegrasikan di fase 5 (VOIN Native L1).")
