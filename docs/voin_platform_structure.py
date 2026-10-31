#!/usr/bin/env python3
"""VOIN platform scaffold: documentation only, no services or funds. Preview by default."""
import argparse
from pathlib import Path
import subprocess

GROUPS = {
 'trade': {
  '': 'Lapisan aplikasi VOIN Trade Payments, terpisah dari konsensus. Fokus awal rancangan invoice B2B; B2C berikutnya. Koridor negara belum dipilih.',
  'domain/invoices': 'Identitas invoice, mata uang tagihan, jumlah decimal/integer, jatuh tempo, pembayaran sebagian dan lebih bayar.',
  'domain/payments': 'Pembayaran terpisah dari status invoice; deduplikasi berdasarkan chain ID dan hash, verifikasi penerima/aset/jumlah/hasil transaksi.',
  'domain/milestones': 'Persetujuan dan pembayaran bertahap. Pencatatan kesepakatan bukan escrow aktif atau bukti barang diterima.',
  'domain/refunds': 'Refund merupakan transaksi baru dengan otorisasi, bukan pembatalan blok atau pengiriman otomatis.',
  'passport': 'Referensi perdagangan menghubungkan invoice, persetujuan, pembayaran dan bukti pengiriman; dokumen rahasia tidak dicatat publik.',
  'storage': 'Kontrak penyimpanan aplikasi privat. File runtime berada di luar Git; tidak membuat database dari pembentuk struktur ini.',
  'adapters/voin': 'Adapter query dan verifikasi transaksi VOIN hanya-baca. RPC tidak otomatis proof-verified.',
  'adapters/partners': 'Kontrak integrasi mitra eksternal; belum ada integrasi, perjanjian, likuiditas, atau izin.',
  'api': 'Kontrak API aplikasi, autentikasi, otorisasi, idempotensi, rate limit dan pengendalian akses.',
  'compliance': 'Antarmuka pemeriksaan negara/layanan, identitas dan risiko sesuai model yang ditinjau. Bukan izin atau keputusan hukum otomatis.',
  'quotes': 'Mata uang invoice, aset settlement dan mata uang pencairan terpisah. Kurs, biaya, kedaluwarsa dan pihak penanggung risiko harus eksplisit.',
  'settlement': 'Pencocokan, finalitas yang didefinisikan, rekonsiliasi dan kegagalan mitra. Settlement blockchain bukan jaminan pencairan fiat.',
  'disputes': 'Rancangan bukti, peran dan proses sengketa; tidak otomatis dapat memutus kebenaran pengiriman barang.',
 },
 'assets': {
  '': 'Spesifikasi multi-aset. Implementasi saldo native yang ada tetap di tempatnya; tidak membuat token on-chain dengan dokumen ini.',
  'registry': 'Identitas aset, issuer, metadata dan desimal; identitas lintas-chain harus eksplisit.',
  'issuance': 'Aturan pasokan, mint/burn, kewenangan, pencabutan dan invariant sebelum perubahan protokol.',
  'stablecoin': 'Riset acuan, issuer, reserve, kewajiban, penebusan dan perizinan. Tidak menerbitkan atau menjamin stablecoin.',
  'gold-reference': 'Harga emas sebagai informasi, bukan klaim cadangan atau penebusan emas. Oracle dan risiko data terpisah.',
 },
 'contracts': {
  '': 'Platform smart contract termasuk roadmap resmi. Belum dipilih VM dan belum ada eksekusi kontrak.',
  'spec': 'Desain kompatibilitas, semantik, versi protokol, model ancaman dan batas kemampuan.',
  'runtime': 'Evaluasi WASM atau EVM sebelum pemilihan. Eksekusi harus deterministik dan terisolasi.',
  'metering': 'Gas/sumber daya, memori, ukuran program, biaya dan penanganan kehabisan sumber daya.',
  'host-interface': 'Antarmuka state, event dan aset yang dibatasi. Tidak ada akses bebas ke filesystem, jaringan, kunci atau proses host.',
  'lifecycle': 'Deploy, panggil, upgrade, izin administrator dan kebijakan kompatibilitas.',
  'templates/trade': 'Spesifikasi kandidat pembayaran bertahap/escrow. Bukan kontrak executable; tidak mengunci dana.',
  'oracles': 'Model kepercayaan bukti eksternal, harga dan pengiriman. Kontrak tidak mengetahui dunia fisik sendiri.',
  'sdk': 'Kontrak perangkat pengembang dan encoding; belum menghasilkan SDK fungsional.',
 },
 'security': {
  'threat-model': 'Ancaman pengguna, validator, operator, dependency dan layanan eksternal; batas kepercayaan dan aset yang dilindungi.',
  'crypto-agility': 'Versi algoritme, migrasi akun, rotasi kunci dan anti-downgrade; bukan mengganti konsensus otomatis.',
  'post-quantum/transactions': 'Petakan ML-DSA transaksi yang ada; audit implementasi, ukuran dan biaya verifikasi.',
  'post-quantum/consensus': 'Riset tanda tangan validator CometBFT secara terpisah; tidak mengklaim konsensus sudah pascakuantum.',
  'post-quantum/transport': 'Riset identitas peer dan perlindungan koneksi terpisah dari tanda tangan transaksi.',
  'access-control': 'Batas wewenang layanan dan operator, least privilege dan audit tindakan.',
 },
 'privacy': {
  'data-map': 'Klasifikasi data publik/privat, tujuan, retensi dan pengungkapan; referensi/hash juga dapat membocorkan metadata.',
  'offchain-storage': 'Rancangan penyimpanan terenkripsi dan akses dokumen terbatas; tidak menyimpan dokumen pribadi di repositori.',
  'selective-disclosure': 'Pengungkapan terbatas yang diotorisasi dan mekanisme pencabutan/masa berlaku.',
  'confidential-transactions': 'Riset jumlah/penerima rahasia dan sistem bukti. Belum implementasi; tidak semua sistem bukti tahan kuantum.',
 },
 'integrations': {
  'marketplaces': 'Kontrak integrasi generik. Tidak mengklaim dukungan atau kerja sama Alibaba/marketplace lain.',
  'identity': 'Kontrak identitas/verifikasi dari penyedia yang ditinjau; tidak menggantikan kewajiban pemeriksaan.',
  'liquidity': 'Kontrak penyedia kurs dan likuiditas; belum ketersediaan dana atau jaminan konversi.',
 },
 'consensus/voin-app/architecture': {
  'multi-asset': 'Batas integrasi multi-aset ke state dan aturan aplikasi, dengan versi/migrasi yang ditinjau.',
  'contract-execution': 'Batas integrasi VM ke ABCI: determinisme, resource metering dan konsistensi hasil antarvalidator.',
  'protocol-upgrades': 'Aturan versi dan koordinasi upgrade. Tidak mengubah genesis atau chain ID dari scaffolder.',
 },
 'docs/architecture': {
  'decisions': 'Catat keputusan dan alternatif: VM belum dipilih; koridor, issuer, aset settlement dan kustodi belum diputuskan.',
 },
}

OVERVIEW = '''# VOIN: peta platform lengkap

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
'''

def planned_files():
    result={}
    for base, entries in GROUPS.items():
        for child, purpose in entries.items():
            name='/'.join(x for x in (base,child,'VOIN-SCOPE.md') if x)
            result[name]='# '+('/'.join(x for x in (base,child) if x))+'\n\n'+purpose+'\n\nStatus: DIRANCANG. Dokumen ini bukan implementasi, hasil tes, kontrak aktif atau izin layanan.\n'
    result['docs/architecture/VOIN-PLATFORM-MAP.md']=OVERVIEW
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    root=Path(subprocess.check_output(['git','rev-parse','--show-toplevel'],text=True).strip()).resolve()
    if not (root/'consensus/voin-app/go.mod').is_file(): raise ValueError('Expected VOIN module not found')
    plan=planned_files()
    for relative in plan:
        target=root/relative
        if target.is_symlink(): raise ValueError('Target symlink refused: '+relative)
        for parent in target.parents:
            if parent==root: break
            if parent.is_symlink(): raise ValueError('Parent symlink refused: '+relative)
        if target.exists() and not target.is_file(): raise ValueError('Target not a regular file: '+relative)
    created=kept=0
    for relative, text in plan.items():
        target=root/relative
        if target.exists():
            kept+=1
            continue
        if args.apply:
            target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('x') as file: file.write(text)
        created+=1
    print(('APPLIED' if args.apply else 'PREVIEW')+':',created,'new scope documents;',kept,'existing kept;',len(plan),'expected total.')
    print('GROUPS: trade, assets, contracts, security, privacy, integrations, voin-app architecture, docs.')
    print('No source replaced or moved; no test data, tests, node changes, keys, transfers, commit or push.')
    print('MAP: docs/architecture/VOIN-PLATFORM-MAP.md')
    if not args.apply: print('Use --apply to create missing structure documentation.')

if __name__=='__main__':
    try: main()
    except Exception as exc:
        print('STOP:',exc)
        print('Partial new files may remain. Do not overwrite existing files to retry.')
        raise SystemExit(1)
