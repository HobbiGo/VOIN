# VOIN: peta platform lengkap

Status: struktur dan spesifikasi tanggung jawab, bukan fitur yang selesai.
Jaringan VOIN -> voin-app -> aset native/multi-aset -> aplikasi pembayaran perdagangan.
Smart contract menjadi lapisan eksekusi terpisah yang perlu diintegrasikan dan diaudit.
Keamanan, privasi dan kepatuhan melintasi seluruh lapisan.

## Urutan kerja
1. Struktur dan pemetaan kode aktual (tahap sekarang).
2. Domain invoice serta kontrak pencocokan pembayaran.
3. Integrasi hanya-baca dan verifikasi pembayaran ke invoice.
4. Desain/implementasi multi-aset dengan peninjauan protokol.
5. Pemilihan VM dan prototipe kontrak terisolasi sebelum aktivasi jaringan.
6. Peninjauan model layanan, koridor dan mitra sebelum konversi/pencairan.
7. Riset stablecoin, privasi dan kriptografi lanjutan sesuai model ancaman.
8. Uji tiap fungsi dan integrasi sebelum penggunaan nyata.

Urutan detail bisa disesuaikan melalui keputusan tertulis. Tes dan data percobaan ditunda
selama pembentukan kerangka, bukan dihilangkan sebagai syarat sebelum penggunaan nyata.
Panduan operasi/pemulihan tetap ditunda sesuai arahan.

## Batas status
Fondasi devnet, signer, dashboard dan satu restart normal sudah pernah diuji dalam sesi.
Multi-aset, kontrak, pembayaran perdagangan, konversi, stablecoin dan privasi di folder
baru adalah rencana. Tidak ada janji nilai, dukungan emas, pencairan, izin lintas negara,
perlindungan kuantum menyeluruh, atau integrasi marketplace dari pembentukan folder.

## Pertahankan sistem yang ada
Kode dalam consensus/voin-app, cmd, walletcrypto dan docs tidak dipindahkan.
Arsitektur baru tidak menimpa source atau mengubah runtime. State, kunci, checkpoint,
invoice nyata, data identitas dan kredensial harus berada di luar Git.
