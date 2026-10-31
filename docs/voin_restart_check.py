#!/usr/bin/env python3
"""Read-only devnet baseline/compare. Does NOT restart anything or prove durability by itself."""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.request import build_opener, ProxyHandler, HTTPRedirectHandler

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None

def collect():
    home = Path.home()
    opener = build_opener(ProxyHandler({}), NoRedirect())
    with opener.open('http://127.0.0.1:29657/status', timeout=8) as response:
        raw = response.read(1000001)
    if len(raw) > 1000000: raise ValueError('Status response too large')
    result = json.loads(raw)['result']
    sync = result['sync_info']
    if result['node_info']['network'] != 'voin-devnet-1': raise ValueError('Unexpected network')
    if sync['catching_up'] is not False: raise ValueError('Node is still catching up')
    public_path = home/'voin-private-devnet-01/wallet-public.json'
    public = json.loads(public_path.read_text())
    accounts = {}
    for name in ('alice', 'bob'):
        address = public[name]['address']
        if not re.fullmatch(r'voin_[0-9a-f]{64}', address): raise ValueError('Invalid public address')
        output = subprocess.run([str(home/'voin-tools/bin/voin-encrypted-wallet'), '-action', 'balance', '-address', address],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15, check=True)
        data = json.loads(output.stdout)
        if 'balance' not in data or 'nonce' not in data: raise ValueError('Account response incomplete')
        accounts[name] = {'address': address, 'balance': data['balance'], 'nonce': data['nonce']}
    processes = []
    root = str(home/'voin-private-devnet-01')
    for p in Path('/proc').iterdir():
        if not p.name.isdigit(): continue
        try:
            args = (p/'cmdline').read_bytes().decode().strip('\0').split('\0')
            if not args or not args[0].startswith(root+'/bin/'): continue
            # Store only argv (no environment or key-file contents).
            processes.append({'pid': int(p.name), 'executable': str((p/'exe').readlink()),
                'cwd': str((p/'cwd').readlink()), 'argv': args,
                'start_ticks': (p/'stat').read_text().rsplit(')',1)[1].split()[19]})
        except (OSError, UnicodeError, IndexError): continue
    if not processes: raise ValueError('No private devnet processes found')
    return {'version': 1, 'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'network': result['node_info']['network'], 'height': int(sync['latest_block_height']),
        'accounts': accounts, 'processes': processes}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['before','after'])
    parser.add_argument('baseline', nargs='?', help='Path printed by before, required for after')
    args = parser.parse_args()
    os.umask(0o077)
    if args.action == 'after' and not args.baseline: parser.error('after requires baseline path')
    old = None
    if args.action == 'after':
        old = json.loads(Path(args.baseline).expanduser().read_text())
        if old.get('version') != 1: raise ValueError('Unsupported baseline')
    current = collect()
    if args.action == 'before':
        folder = Path.home()/'voin-restart-records'
        if folder.is_symlink(): raise ValueError('Records directory cannot be symlink')
        folder.mkdir(mode=0o700, exist_ok=True)
        if folder.stat().st_mode & 0o077: raise ValueError('Records directory must be private')
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        target = folder/('before-'+stamp+'.json')
        with target.open('x') as f: json.dump(current, f, indent=2)
        print('BASELINE:', target)
        print('HEIGHT:', current['height'])
        for name, data in current['accounts'].items(): print(name.upper(), 'balance=',data['balance'],'nonce=',data['nonce'])
        print('PROCESSES:', len(current['processes']))
        print('Baseline saved outside Git. NO node was stopped. This is NOT a restart test PASS.')
    else:
        if old['network'] != current['network']: raise ValueError('Network changed')
        if old['accounts'] != current['accounts']: raise ValueError('Accounts differ. Check concurrent transfers; do not reset or resend.')
        if current['height'] <= old['height']: raise ValueError('Height has not advanced')
        before = {(p['pid'],p['start_ticks']) for p in old['processes']}
        after = {(p['pid'],p['start_ticks']) for p in current['processes']}
        print('ACCOUNTS MATCH; HEIGHT ADVANCED:',old['height'],'->',current['height'])
        if before == after:
            print('NO PROCESS RESTART OBSERVED. This does not prove restart durability.')
        else:
            print('PROCESS SET CHANGED. Correlate with controlled restart logs; this alone does not prove checkpoint integrity or crash safety.')
    print('Read-only RPC results; no cryptographic proof verification. No key reads, transfers, deletion, commit or push.')

if __name__ == '__main__':
    try: main()
    except KeyboardInterrupt: raise SystemExit(130)
    except Exception as exc:
        print('STOP:',str(exc))
        raise SystemExit(1)
