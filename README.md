# VOIN Experimental Blockchain Simulator

Prototipe ledger lokal berbasis Python, bukan komputer kuantum,
jaringan cryptocurrency, atau sistem siap produksi.

## Menjalankan

Gunakan Python 3.12 dan jalankan:

    python -m pip install -r requirements.txt
    python demo_signed.py
    python -m unittest discover -s tests -v

## Dua versi ledger

- VoinChain di voin.py: simulator awal tanpa autentikasi transaksi.
- SignedVoinChain di signed_chain.py: mewajibkan tanda tangan
  ML-DSA-44 dan mencocokkan alamat pengirim dengan public key.

Demo signed membuat kunci sementara di memori dan mengirim
250 unit simulasi dari saldo awal 1000. Bukan uang nyata.

## Status pengujian

11 pengujian lokal lulus saat pengembangan.
Workflow Add signed ledger juga berhasil di GitHub Actions.
Hasil ini bukan audit keamanan.

## Batasan

Tidak ada jaringan peer-to-peer, persistensi, pengelolaan kunci
produksi, atau konsensus Proof of Stake. Validator hanya metadata
demo. Proof of Work sangat sederhana dan tidak aman untuk produksi.

Pustaka pqcrypto 1.0.0 menyatakan implementasinya belum menjalani
audit keamanan formal. Tanda tangan tidak membuat seluruh sistem
otomatis aman terhadap semua serangan.

Jangan gunakan untuk dana nyata. Jangan unggah kunci privat.
