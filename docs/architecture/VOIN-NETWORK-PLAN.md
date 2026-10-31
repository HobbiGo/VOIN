# VOIN: struktur jaringan dan aplikasi

## Status paket
Ini peta arsitektur dan dokumentasi struktur, BUKAN implementasi jaringan baru.
Tidak ada file Go baru, dependency baru, genesis baru, atau layanan yang diluncurkan.
Jaringan aktif, wallet, validator key, state, serta kode lama tidak diubah.

## Aliran tanggung jawab
Peer/validator -> CometBFT -> ABCI -> aplikasi VOIN -> validasi transaksi -> state/commit.
Wallet menandatangani dengan persetujuan pengguna; node memvalidasi, bukan mempercayai wallet.
Dashboard -> query hanya-baca -> RPC/aplikasi; tidak pernah menerima kunci/passphrase.

## Turunan voin-app
- go.mod/go.sum: modul Go existing, dipertahankan.
- package root existing: implementasi aktual tetap di tempat semula.
- cmd/ existing: program executable tetap di tempat semula.
- walletcrypto/ existing: penyimpanan terenkripsi tetap di tempat semula.
- architecture/abci: batas protokol ABCI.
- architecture/state: akun, saldo, nonce, height, invariant.
- architecture/transactions: format transaksi dan chain ID.
- architecture/validation: penolakan transaksi dan aturan perubahan state.
- architecture/signatures: verifikasi tanda tangan dan domain separation.
- architecture/queries: kontrak query dan proof verification.
- architecture/persistence: commit dan checkpoint.
- architecture/testing: pemetaan tes ke fungsi.

Folder architecture adalah spesifikasi, bukan package Go kosong yang dianggap sudah berjalan.
Pemisahan source menjadi package baru baru dilakukan setelah dependency dan kompatibilitas ditinjau.

## Urutan pengembangan
1. Inventaris implementasi aktual dan petakan ke tanggung jawab di atas.
2. Jaringan: kontrak konfigurasi publik dan validasi pemetaan port/peer/chain.
3. voin-app: lengkapi invariant transaksi berdasarkan kode dan tes yang sudah ada.
4. Integrasi: query saldo, transaksi, state/commit, dan kesepakatan hasil antar node.
5. Wallet/dashboard: konsolidasi antarmuka tanpa akses kunci dari dashboard.
6. Pemeriksaan satu per satu, lalu satu pemeriksaan integrasi paket.

Setiap fungsi diberi status: direncanakan, kode ditemukan/belum ditinjau, diuji terbatas,
atau diverifikasi pada lingkungan tertentu. Folder ada bukan berarti fungsi selesai.

## Bukti sesi sebelumnya (bukan hasil tes scaffolder)
- Devnet 4 validator dengan power 1 per validator pernah terbaca dari RPC.
- Transfer signer terenkripsi dan query dashboard pernah berhasil.
- Restart normal satu pasangan node/aplikasi pernah lolos dengan saldo/nonce tetap.
- Cakupan itu bukan bukti kesiapan mainnet, crash safety, atau keamanan produksi.

## Pekerjaan yang tetap tertunda
Verifikasi checksum backup perangkat, penanganan plaintext lama, audit keamanan,
proof verification independen, serta panduan operasi/pemulihan yang diminta untuk ditunda.

## Batas keamanan
Tidak menaruh rahasia atau data runtime dalam struktur ini.
Tidak memindahkan/menimpa source, mengubah genesis, mengubah chain ID,
mengirim transaksi, merestart node, atau commit/push otomatis.
