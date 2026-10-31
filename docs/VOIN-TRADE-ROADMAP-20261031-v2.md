# VOIN Trade Payments: tahapan pembangunan

Status: arah pengembangan, bukan klaim fitur selesai, izin operasi, atau jaminan nilai aset.
Tanggal: 2026-10-31.

## Tujuan yang dikunci
VOIN sebagai jaringan blockchain inti; VOIN Trade Payments sebagai lapisan aplikasi pembayaran perdagangan lintas negara B2B/B2C. Fokus awal disarankan invoice B2B. Belum dipilih koridor negara, penerbit aset, kustodian, atau mitra pencairan.

## Fondasi yang pernah diuji
Devnet CometBFT empat validator lokal berbobot sama, transfer unit uji melalui signer terenkripsi, saldo/nonce, dashboard hanya-baca, serta restart normal satu pasangan dengan checkpoint. Struktur arsitektur sudah tersimpan. Ini bukan bukti jaringan produksi, transaksi privat, stabilitas harga, atau perlindungan pascakuantum menyeluruh.

## Tahap 1 — Model perdagangan dan invoice
Buat lapisan aplikasi terpisah, jangan mengubah konsensus atau saldo yang ada.
- Identitas invoice, referensi pembeli/penjual, tanggal jatuh tempo.
- Mata uang invoice terpisah dari aset penyelesaian.
- Jumlah memakai representasi integer/decimal yang eksplisit, bukan float.
- Status invoice: draft, issued, cancelled, expired; status pembayaran terpisah agar transaksi terlambat tidak hilang.
- Model pembayaran sebagian dan lebih bayar, tanpa menjamin otomatis diterima.
- Identitas chain dan hash transaksi untuk deduplikasi; hash yang sama tidak boleh dicatat dua kali.
- Lampiran hash semata bukan bukti pembayaran: perlu verifikasi chain, hasil eksekusi, penerima, aset, jumlah, dan aturan konfirmasi.
- Tidak menaruh identitas pribadi atau invoice lengkap pada blockchain publik.
Keluaran: model domain, penyimpanan aplikasi lokal terpisah, API lokal yang belum melayani dana nyata, dokumentasi kontrak.

## Tahap 2 — Pencocokan pembayaran jaringan
Adapter hanya-baca untuk memverifikasi transaksi dan mencocokkan invoice. Pencatatan idempoten, penanganan hasil RPC tidak tersedia, audit trail, serta status pending/verified/rejected. Refund adalah pembayaran keluar baru yang perlu otorisasi, bukan pembatalan blok.
Keluaran: alur invoice ke bukti pembayaran pada devnet, tanpa konversi fiat.

## Tahap 3 — Aset dan kontrak penyelesaian
Petakan dukungan aset native saat ini. Rancang identitas aset, metadata desimal, saldo per aset, issuer, supply, mint/burn permissions dan invariant sebelum mengubah state/encoding konsensus. Perubahan protokol membutuhkan versi dan rencana migrasi. Jangan membuat tabel aplikasi yang disalahartikan sebagai token on-chain.
Keluaran: spesifikasi multi-aset dan implementasi bertahap setelah tinjauan kode aktual.

## Tahap 4 — Kepatuhan dan model layanan
Pilih koridor, jenis pengguna, kustodi/nonkustodi, aset, dan tanggung jawab pihak. Tinjau bersama penasihat yang kompeten serta calon mitra. Rancang kontrol akses, pemeriksaan yang diperlukan, batas transaksi, penanganan kasus, retensi dan penghapusan data privat. Penyimpanan data dan pemrosesan lintas negara perlu ditinjau tersendiri.
Keluaran: model layanan dan persyaratan yurisdiksi yang telah ditinjau, bukan izin yang diciptakan oleh kode.

## Tahap 5 — Penawaran kurs dan likuiditas
Pisahkan mata uang invoice, aset penyelesaian, dan mata uang pencairan. Kutipan kurs memiliki masa berlaku, biaya eksplisit, jumlah bersih, dan penanggung risiko yang ditetapkan. Integrasi mitra dilakukan setelah kelayakan layanan jelas. Jangan mengklaim menjamin nilai tukar tanpa dukungan operasional.
Keluaran: adapter penawaran dan rekonsiliasi; belum otomatis layanan finansial publik.

## Tahap 6 — Stablecoin (proyek terpisah)
Utamakan evaluasi integrasi aset dari penerbit yang sesuai sebelum penerbitan sendiri. Jika menerbitkan sendiri, tentukan acuan, cadangan, kustodian, kewajiban, hak penebusan, likuiditas, kontrol mint/burn, audit, dan perizinan. Jangan menyamakan unit uji dengan stablecoin atau menjanjikan peg algoritmik.
Acuan emas berbeda dari acuan mata uang invoice. Harga emas sebagai informasi tidak berarti dukungan emas atau hak penebusan.

## Tahap 7 — Privasi dan proteksi kriptografi
Tentukan model ancaman dan minimasi data lebih dahulu. Pertahankan pengungkapan terbatas yang sah/diotorisasi. Riset sistem bukti secara terpisah. Petakan ML-DSA transaksi versus tanda tangan validator, peer dan transport. Rancang versi algoritme, rotasi, migrasi dan anti-downgrade. Tidak mengklaim seluruh jaringan quantum-proof.

## Tahap 8 — Platform smart contract
Termasuk dalam arah resmi atas permintaan merchant. Belum diimplementasikan.
Pisahkan desain dan spesifikasi sekarang dari aktivasi eksekusi kontrak pada jaringan.
- Tentukan lingkungan eksekusi (misalnya WASM atau EVM) setelah evaluasi, bukan mengaktifkan keduanya tanpa kebutuhan.
- Eksekusi deterministik antarvalidator, metering sumber daya/gas, sandbox, batas memori dan ukuran kode.
- Aturan deploy, pemanggilan, penyimpanan, versi, upgrade, dan otorisasi.
- Isolasi kontrak dari filesystem host, jaringan eksternal, kunci, dan proses node.
- Interaksi dengan aset native/multi-aset, event, query dan SDK.
- Pengujian kegagalan, pengurasan sumber daya, reentrancy jika relevan, audit dan testnet terisolasi.
- Program tidak mengetahui pengiriman barang atau harga eksternal sendiri; oracle dan sengketa memerlukan model kepercayaan terpisah.
Use case kandidat: pembayaran bertahap dan escrow perdagangan. Jangan mengunci dana nyata sebelum keamanan, mekanisme sengketa, serta model layanan ditinjau.
Tanda tangan transaksi ML-DSA tidak otomatis membuat seluruh VM atau sistem bukti pascakuantum aman.
Keluaran: spesifikasi platform, prototipe terisolasi, lalu evaluasi sebelum integrasi konsensus atau pilot.

## Tahap 9 — Pilot terbatas sebelum publik
Uji terisolasi per fungsi dan integrasi, tinjau keamanan independen, ketahanan, rekonsiliasi, sengketa, serta kegagalan mitra. Baru pertimbangkan pilot sesuai koridor dan persyaratan yang disetujui. Jangan memakai dana nyata hanya karena folder dan kode tersedia.

## Struktur tujuan lapisan aplikasi
trade/domain/         model invoice, money, payment dan aturan status
trade/storage/        penyimpanan aplikasi privat; runtime di luar Git
trade/adapters/voin/  query dan verifikasi transaksi
trade/api/            akses terautentikasi dan kontrak API
trade/compliance/     antarmuka kebijakan; bukan klaim izin
trade/quotes/         kontrak penawaran kurs, belum harga terjamin
trade/docs/           spesifikasi serta batas tahap

Folder ini adalah rancangan tujuan; dokumen roadmap tidak membuatnya atau mengimplementasikan fungsi.

## Cara bekerja
Bangun paket yang koheren, pertahankan source dan state yang ada. Pembuatan data percobaan dan tes fungsi ditunda selama penyusunan struktur, tetapi verifikasi fungsi wajib sebelum klaim selesai atau penggunaan nyata. Tidak ada transfer, restart, migrasi state, commit atau push otomatis. Panduan operasi/pemulihan tetap ditunda sesuai arahan merchant.
