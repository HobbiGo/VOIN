# VOIN: Wallet Uji Terenkripsi

Hanya untuk devnet, bukan dana nyata. KIRIM bukan 2FA atau multisig.

## Sudah diuji
Pemeriksaan wallet, backup lokal, pemulihan ke file terpisah, dan transfer terenkripsi berhasil. Alice -1, Bob +1, nonce naik sekali. Kode signer: commit 4a0aa38.

## Aturan penggunaan
Masukkan passphrase hanya saat prompt passphrase muncul, bukan pada prompt shell $. Ketikan tersembunyi adalah normal. Periksa jaringan, penerima, jumlah, dan nonce sebelum menyetujui transfer dengan KIRIM. Jika SUBMITTED muncul lalu error, periksa status hash sebelum mencoba lagi.

## Backup dan keamanan
Simpan backup terenkripsi di perangkat terpisah dan passphrase di pengelola kata sandi. Jangan unggah wallet, backup, atau passphrase ke Git atau chat. Gunakan nama baru untuk uji pemulihan, jangan timpa wallet lama.

## Belum selesai
Checksum backup unduhan belum dibandingkan. Kunci plaintext lama masih ada; jangan dihapus dulu. Audit keamanan dan kesiapan produksi belum selesai.
