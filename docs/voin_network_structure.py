#!/usr/bin/env python3
"""Add a VOIN network architecture scaffold without moving or replacing existing code.
Default: preview. --apply exclusively creates missing documentation files.
Does not implement a running network, run tests, start nodes, or alter wallet/state.
"""
import argparse
from pathlib import Path
import subprocess

MODULES = {
    'network': ('Lapisan jaringan', 'Peta konfigurasi, topologi, dan spesifikasi jaringan. Node tidak dimulai dari pembentuk struktur ini.'),
    'network/topology': ('Topologi', 'Rencanakan validator, peer, dan lingkungan devnet. Empat validator berbobot sama pernah diverifikasi dalam sesi ini; jangan menganggap konfigurasi ini permanen.'),
    'network/config': ('Konfigurasi publik', 'Spesifikasi chain ID, port, dan parameter publik. Jangan menaruh private validator key, node key, passphrase, state runtime, atau genesis baru di sini tanpa peninjauan.'),
    'network/peers': ('Peer dan konektivitas', 'Spesifikasi koneksi peer, pengamatan koneksi, dan validasi konfigurasi. Implementasi jaringan tetap menggunakan CometBFT yang ada.'),
    'network/rpc': ('Kontrak RPC hanya-baca', 'Dokumentasikan status, blok, validator, saldo, dan transaksi. Jangan membangun proxy RPC umum atau endpoint pengiriman tanpa desain keamanan terpisah.'),
    'network/health': ('Kesehatan jaringan', 'Rencanakan pengamatan tinggi blok, sinkronisasi, dan keterjangkauan node. Folder ini belum berisi monitor yang berjalan.'),
    'consensus': ('Lapisan konsensus', 'Pertahankan integrasi CometBFT dan modul Go yang ada. Folder baru tidak mengubah aturan konsensus.'),
    'consensus/voin-app': ('Aplikasi VOIN', 'Akar modul Go yang ada. go.mod, package root, dan cmd yang ada TIDAK dipindahkan atau ditimpa. Turunan baru berikut hanya peta pemisahan tanggung jawab, bukan package Go terimplementasi.'),
    'consensus/voin-app/architecture/abci': ('ABCI', 'Peta koneksi aplikasi dengan CometBFT, urutan pemrosesan blok, query, dan commit. Implementasi aktual harus dipetakan dari kode sebelum perubahan.'),
    'consensus/voin-app/architecture/state': ('State', 'Spesifikasi akun, saldo, nonce, height, persistensi, dan invariant. Bukan lokasi state runtime.'),
    'consensus/voin-app/architecture/transactions': ('Transaksi', 'Spesifikasi encoding, chain ID, pengirim, penerima, jumlah, nonce, dan batas input. Pertahankan kompatibilitas transaksi lama sampai migrasi dirancang.'),
    'consensus/voin-app/architecture/validation': ('Validasi', 'Rencanakan pengujian jumlah, saldo tidak cukup, nonce, tanda tangan, replay, dan tidak berubahnya state saat penolakan. Jangan membuat ulang implementasi sebelum meninjau kode dan tes yang ada.'),
    'consensus/voin-app/architecture/signatures': ('Tanda tangan', 'Dokumentasikan algoritme dan domain separation dari kode aktual. Jangan mengganti algoritme, format tanda tangan, atau model kepercayaan diam-diam.'),
    'consensus/voin-app/architecture/queries': ('Query', 'Kontrak saldo, nonce, status transaksi, dan batas klaim proof verification. Respons RPC bukan otomatis bukti terverifikasi.'),
    'consensus/voin-app/architecture/persistence': ('Persistensi dan checkpoint', 'Catat batas commit, checkpoint tepercaya lokal, dan startup dari state lama. Uji restart normal satu pasangan sudah pernah lolos; bukan bukti crash safety.'),
    'consensus/voin-app/architecture/testing': ('Peta tes voin-app', 'Petakan tes aktual ke invariant. Pisahkan unit test, integrasi, devnet, dan pengujian berisiko. Tidak menjalankan tes dari scaffolder.'),
    'wallet': ('Antarmuka wallet', 'Rencana konsolidasi alat wallet. CLI, signer, dan walletcrypto yang ada tidak dipindahkan. Semua wallet asli tetap di luar repositori.'),
    'wallet/cli': ('CLI wallet', 'Peta perintah publik dan pengiriman. Jangan menyimpan password, menerima private key melalui argumen, atau menghilangkan persetujuan eksplisit.'),
    'wallet/storage': ('Penyimpanan terenkripsi', 'Peta integrasi walletcrypto yang sudah ada. Jangan membuat salinan state/key ke folder ini.'),
    'dashboard': ('Dashboard', 'Peta konsolidasi dashboard hanya-baca. Versi utama saat ini berada di docs/voin_dashboard.py; tidak dipindahkan oleh paket ini.'),
    'tools': ('Alat pengembangan', 'Peta konsolidasi pemeriksa. Skrip lama dalam docs tetap dipertahankan; tidak ada peluncuran otomatis.'),
    'tests/network': ('Tes jaringan', 'Rencana tes konektivitas, kesamaan chain, voting power, dan kemajuan blok. Belum implementasi tes.'),
    'tests/integration': ('Tes integrasi', 'Rencana tes antar CLI, aplikasi, RPC, dan dashboard. Gunakan kunci sintetis dan lingkungan terisolasi.'),
    'docs/architecture': ('Dokumen arsitektur', 'Gunakan VOIN-NETWORK-PLAN.md untuk batas tahap dan urutan implementasi.'),
}

PLAN = '''# VOIN: struktur jaringan dan aplikasi

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
'''

def files():
    result = {}
    for folder, (title, purpose) in MODULES.items():
        result[folder+'/VOIN-MODULE.md'] = '# '+title+'\n\n'+purpose+'\n\nStatus: dokumentasi/rencana. Keberadaan file ini bukan bukti implementasi atau hasil pengujian.\n'
    result['docs/architecture/VOIN-NETWORK-PLAN.md'] = PLAN
    return result

def safe_target(root, relative):
    target = root/relative
    if target.is_symlink(): raise ValueError('Symlink target refused: '+relative)
    for parent in target.parents:
        if parent == root: break
        if parent.is_symlink(): raise ValueError('Symlink parent refused: '+relative)
    if target.exists() and not target.is_file(): raise ValueError('Target is not a regular file: '+relative)
    return target

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    root=Path(subprocess.check_output(['git','rev-parse','--show-toplevel'],text=True).strip()).resolve()
    if not (root/'consensus/voin-app/go.mod').is_file(): raise ValueError('Expected VOIN Go module not found')
    planned=files()
    targets={name:safe_target(root,name) for name in planned}
    created=0
    skipped=0
    for name,content in planned.items():
        target=targets[name]
        if target.exists():
            print('KEEP:',name)
            skipped+=1
            continue
        if args.apply:
            target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('x') as f: f.write(content)
            print('CREATED:',name)
        else:
            print('PLAN:',name)
        created+=1
    print(('APPLIED' if args.apply else 'PREVIEW')+':',created,'new documentation files;',skipped,'existing files kept.')
    print('No source moved/replaced. No node start, restart, key read, transaction, test, commit or push.')
    if not args.apply: print('Use --apply to create the missing documentation files.')

if __name__=='__main__':
    try: main()
    except Exception as exc:
        print('STOP:',exc)
        print('Do not assume partial creation was rolled back. Existing files are never intentionally overwritten.')
        raise SystemExit(1)
