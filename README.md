# VOIN Experimental Blockchain Prototype

Prototipe ledger lokal dengan tanda tangan ML-DSA-44.
Bukan mainnet, exchange, komputer kuantum, atau sistem siap produksi.

## Menjalankan

Gunakan Python 3.12:

    python -m pip install -r requirements.txt
    python demo_strict.py
    python -m unittest discover -s tests -v

Demo menghasilkan saldo Alice 850, Bob 150, dan integritas True.
Kunci demo dibuat sementara di memori, bukan disimpan.

## Versi terbaru

StrictVoinChain menggabungkan:
- Transaksi v2 dengan chain_id yang ikut ditandatangani.
- Alamat pengirim dan penerima berformat hash public key.
- Batas input kunci, tanda tangan, dan jumlah transaksi.
- Genesis deterministik untuk konfigurasi yang sama.
- Pemeriksaan struktur blok.
- Validasi calon rantai sebelum mengganti rantai aktif.

File ledger dan demo lama tetap untuk referensi.
Jangan gunakan versi lama sebagai layanan transaksi.

## Pengujian

32 tes lokal lulus saat pengembangan.
GitHub Actions Add strict ledger demo juga berhasil.
Tes tersebut bukan audit atau bukti keamanan menyeluruh.

## Batasan penting

Belum ada jaringan peer-to-peer, konsensus antarvalidator,
tanda tangan validator, persistensi, atau keamanan akses bersamaan.
Data dan konfigurasi masih berupa objek Python lokal yang bisa diubah.
Salinan seluruh rantai digunakan saat penambahan blok, sehingga
belum cocok untuk target TPS tinggi.

Genesis sama hanya jika konfigurasi dan alokasi awal sama.
Demo memakai kunci acak, sehingga genesis berbeda setiap dijalankan.
Nama voin-devnet-1 belum berarti ada devnet antarserver.

Pustaka pqcrypto 1.0.0 menyatakan implementasinya belum diaudit
secara formal. Jangan gunakan untuk dana nyata atau unggah kunci privat.

## Arah pengembangan

Tujuan: blockchain mandiri terdesentralisasi dan exchange terpusat
sebagai produk terpisah yang dapat dihubungkan.
Belum ada benchmark yang membuktikan lebih cepat dari Solana.
