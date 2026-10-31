#!/usr/bin/env python3
"""Experimental VOIN read-only dashboard. Standard library only.
No signing, wallet-file access, generic RPC proxy, or static file serving.
Run: python FILE.py --selftest, then python FILE.py
Keep any Codespaces forwarded port PRIVATE.
"""
import argparse
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import subprocess
import threading
from urllib.parse import parse_qs, urlsplit
from urllib.request import build_opener, ProxyHandler, HTTPRedirectHandler

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def network_summary():
    opener = build_opener(ProxyHandler({}), NoRedirect())
    summary = {'proof_verified': False, 'note': 'Status dan blok dibaca terpisah; height bisa berbeda.'}
    for endpoint in ('status', 'block'):
        try:
            with opener.open('http://127.0.0.1:29657/' + endpoint, timeout=6) as response:
                raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise ValueError('Respons melebihi batas 2 MB')
            result = json.loads(raw)['result']
            if endpoint == 'status':
                node, sync = result['node_info'], result['sync_info']
                summary['network'] = {'chain_id': node['network'], 'height': sync['latest_block_height'],
                    'time': sync['latest_block_time'], 'catching_up': sync['catching_up']}
            else:
                block = result['block']
                summary['latest_block'] = {'height': block['header']['height'], 'time': block['header']['time'],
                    'hash': result['block_id']['hash'], 'transactions': len(block['data'].get('txs') or [])}
        except Exception:
            summary[endpoint + '_error'] = 'Tidak dapat membaca respons node lokal. Cek proses devnet; tidak dicoba ulang otomatis.'
    return summary

BINARY = Path.home() / 'voin-tools/bin/voin-encrypted-wallet'
LIMIT = threading.BoundedSemaphore(2)

def command_for(action, value):
    if action == 'balance' and re.fullmatch(r'voin_[0-9a-f]{64}', value):
        return ['-action', 'balance', '-address', value]
    if action == 'status' and re.fullmatch(r'[0-9a-fA-F]{64}', value):
        return ['-action', 'status', '-hash', value]
    raise ValueError('Alamat harus voin_ + 64 hex kecil; hash harus 64 hex tanpa 0x. Pilih aksi yang sesuai.')

def query(action, value):
    if action == 'network':
        if value:
            raise ValueError('Kosongkan kolom alamat/hash untuk status jaringan.')
        if not LIMIT.acquire(blocking=False):
            raise ValueError('Sedang memproses permintaan lain. Coba lagi nanti.')
        try:
            return network_summary()
        finally:
            LIMIT.release()
    args = command_for(action, value)
    if not BINARY.is_file():
        raise ValueError('Binary voin-encrypted-wallet tidak ditemukan. Tidak melakukan instalasi otomatis.')
    if not LIMIT.acquire(blocking=False):
        raise ValueError('Sedang memproses permintaan lain. Tunggu lalu coba lagi.')
    try:
        result = subprocess.run([str(BINARY), *args], stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=12, check=False)
        if result.returncode:
            raise ValueError('Permintaan gagal. Pastikan devnet aktif dan alamat/hash benar. Tidak ada percobaan ulang otomatis.')
        if len(result.stdout) > 131072:
            raise ValueError('Respons terlalu besar untuk ditampilkan.')
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        raise ValueError('Permintaan melewati 12 detik. Tidak dicoba ulang otomatis.')
    except json.JSONDecodeError:
        raise ValueError('Respons program bukan JSON yang valid.')
    finally:
        LIMIT.release()

def page(result='', error='', action='balance', value=''):
    esc = html.escape
    choices = ''.join('<option value="'+a+'"'+(' selected' if action == a else '')+'>'+label+'</option>'
        for a, label in [('network', 'Status jaringan dan blok terbaru'), ('balance', 'Saldo alamat'), ('status', 'Status transaksi')])
    return ('''<!doctype html><html lang="id"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>VOIN Devnet</title>
<style>body{background:#101827;color:#e5edf9;font:16px system-ui;margin:auto;padding:32px 20px;max-width:850px}small,p{color:#b8c6d9}h1{color:#72e3bb}section{background:#1a263b;padding:24px;border-radius:16px;margin:20px 0}label{display:block;margin:14px 0 6px}input,select,button{box-sizing:border-box;font:inherit;border-radius:8px;padding:12px;width:100%;border:1px solid #51627d}button{background:#72e3bb;color:#101827;margin-top:18px;cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere}aside{color:#ffcb8b}</style>
<h1>VOIN / Devnet Explorer</h1><p>Dashboard eksperimental hanya-baca. Bukan mainnet atau dompet produksi.</p>
<section><form method="get" action="/"><label for="action">Pemeriksaan</label><select id="action" name="action">'''+choices+'''</select>
<label for="value">Alamat publik atau hash transaksi</label><input id="value" name="value" maxlength="69" autocomplete="off" value="'''+esc(value, quote=True)+'''">
<small>Jangan masukkan private key atau passphrase. Hash tanpa awalan 0x.</small><button type="submit">Periksa</button></form></section>'''+
        ('<section><aside>'+esc(error)+'</aside></section>' if error else '')+
        ('<section><h2>Hasil RPC</h2><pre>'+esc(result)+'</pre></section>' if result else '')+
        '<p>Data berasal dari RPC melalui binary lokal. Dashboard tidak memverifikasi bukti kriptografis. Tidak tersedia pengiriman, tanda tangan, atau akses file wallet.</p><small>Alamat/hash dalam URL dapat tersimpan di riwayat browser. Port Codespaces harus tetap Private. Untuk status jaringan, pilih opsinya dan kosongkan kolom alamat/hash. Waktu blok ditampilkan sesuai respons node (UTC).</small></html>')

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Do not log addresses or transaction hashes.
    def do_GET(self):
        if len(self.path) > 512:
            self.send_error(414)
            return
        parts = urlsplit(self.path)
        if parts.path != '/':
            self.send_error(404)
            return
        action, value, output, error = 'balance', '', '', ''
        try:
            params = parse_qs(parts.query, keep_blank_values=True, max_num_fields=3)
            if params:
                if set(params) != {'action', 'value'} or any(len(v) != 1 for v in params.values()):
                    raise ValueError('Parameter tidak valid.')
                action = params['action'][0]
                value = params['value'][0]
                output = json.dumps(query(action, value), indent=2, ensure_ascii=False)
        except (ValueError, OSError) as exc:
            error = str(exc)
        content = page(output, error, action, value).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(content)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(content)
    def do_POST(self):
        self.send_error(405)

def selftest():
    import unittest
    class Tests(unittest.TestCase):
        def test_balance(self):
            self.assertEqual(command_for('balance', 'voin_'+'a'*64), ['-action','balance','-address','voin_'+'a'*64])
        def test_status(self):
            self.assertEqual(command_for('status','b'*64), ['-action','status','-hash','b'*64])
        def test_block_signing(self):
            for a in ('send','new','check','../wallet'):
                with self.assertRaises(ValueError): command_for(a,'a'*64)
        def test_invalid_input(self):
            for a, v in [('balance','x'),('status','0x'+'a'*64),('balance','voin_'+'g'*64),('status','a'*64+';ls')]:
                with self.assertRaises(ValueError): command_for(a,v)
        def test_escape(self):
            rendered = page('<script>x</script>', '<img>', value='" onfocus="bad')
            self.assertNotIn('<script>', rendered)
            self.assertNotIn('<img>', rendered)
            self.assertIn('&lt;script&gt;', rendered)
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    print('SELFTEST: pas de wallet, RPC, transfert, ni serveur demarre.' if False else 'SELFTEST: tidak memanggil wallet/RPC atau memulai server.')
    return 0 if result.wasSuccessful() else 1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selftest', action='store_true')
    parser.add_argument('--port', type=int, default=8787)
    args = parser.parse_args()
    if args.selftest:
        raise SystemExit(selftest())
    if not 1024 <= args.port <= 65535:
        parser.error('Port harus 1024-65535')
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    print('VOIN read-only: http://127.0.0.1:'+str(args.port), flush=True)
    print('Codespaces: forward port ini dengan visibility PRIVATE. Ctrl+C untuk berhenti.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
