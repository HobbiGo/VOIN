# VOIN Blockchain Simulator

Prototipe ledger lokal untuk belajar blockchain. Bukan komputer kuantum, bukan jaringan cryptocurrency, bukan produk siap produksi, dan tidak mengimplementasikan kriptografi post-quantum.

## Persyaratan dan menjalankan

Python 3.10+; hanya memakai standard library, tanpa instalasi paket tambahan.

```sh
python voin.py
python -m unittest discover -s tests -v
```

Pada sebagian perangkat gunakan `python3` sebagai pengganti `python`.

Demo membuat saldo awal alice 1000 unit simulasi lalu mengirim 250 ke bob. Saldo akhir yang diharapkan: alice 750, bob 250. Nilai ini bukan uang/token nyata.

## Fitur

- Hash SHA-256 dan linkage antarblok.
- Proof of Work sederhana dengan difficulty terbatas 0–4.
- Pemeriksaan saldo, nominal integer positif, dan nonce per pengirim.
- Replay transaksi untuk pemeriksaan konsistensi rantai.
- Penolakan validator demo yang belum terdaftar.
- Pengujian unit untuk transfer, replay, perubahan data, saldo, dan atomicity batch.

## Batas keamanan penting

Tidak ada tanda tangan transaksi atau autentikasi pengirim. Siapa pun yang mengakses objek Python ini dapat mengirim atas nama akun mana pun yang memiliki saldo. Nonce mencegah pengulangan transaksi yang sama, BUKAN pemalsuan identitas.

Pendaftaran validator hanya metadata demo. Stake tidak diambil dari saldo, tidak dikunci, dan tidak menentukan pemilihan validator. Ini bukan Proof of Stake, Q-PoS, atau konsensus jaringan.

Pemeriksaan hash mendeteksi perubahan yang tidak disertai perhitungan ulang, tetapi bukan perlindungan terhadap penyerang yang bisa menulis ulang rantai dan menghitung ulang proof of work. Difficulty sangat rendah dan tidak aman. Genesis anchor hanya hidup di memori proses yang sama. Registri validator dan difficulty juga dapat diubah oleh pemanggil lokal.

Tidak ada persistensi, dompet, kunci privat/publik, jaringan peer-to-peer, fork choice, finality, API publik, reward, slashing, atau audit keamanan. Data hilang ketika proses berakhir. Jangan gunakan untuk dana, aset, kredensial, atau data sensitif.

## Rencana post-quantum

Tahap berikutnya memerlukan pustaka kriptografi terawat dengan implementasi tanda tangan standar seperti ML-DSA, pengikatan alamat ke public key, serialisasi pesan yang konsisten, domain separation, signature per transaksi, pengelolaan kunci, serta pengujian dan audit. Pemeriksaan awalan teks seperti `PQC_SIG_` bukan verifikasi kriptografi. Proyek ini sengaja tidak menyediakan verifier palsu.

## Unggah ke GitHub

Buat repository kosong bernama `voin-blockchain-simulator`, lalu unggah `voin.py`, `README.md`, `.gitignore`, dan direktori `tests` dengan struktur tetap sama. Jangan unggah kunci privat atau rahasia.

Alternatif melalui terminal, dari direktori proyek setelah repository kosong dibuat:

```sh
git init
git add .
git commit -m "Add educational VOIN ledger simulator"
git branch -M main
# Ganti OWNER dengan akun GitHub Anda.
git remote add origin https://github.com/OWNER/voin-blockchain-simulator.git
git push -u origin main
```

## Status verifikasi paket

Kode dan sembilan kasus pengujian telah disiapkan. Pengujian BELUM dijalankan di lingkungan pembuat paket karena runtime Python tidak tersedia. Jalankan perintah pengujian di atas sebelum mengembangkan lebih lanjut.
