#!/usr/bin/env python3
"""Experimental single-pair graceful restart for the known VOIN private devnet.
Requires voin_restart_check.py in this directory. Default: preflight only.
No genesis reset, key access, transactions, forced kill, commit or push.
Not a crash-safety test. Keep the terminal open during an approved restart.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import time
import tomllib
from urllib.request import build_opener, ProxyHandler, HTTPRedirectHandler

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None

OPENER = build_opener(ProxyHandler({}), NoRedirect())
ROOT = Path.home()/'voin-private-devnet-01'

def rpc(port, endpoint):
    if endpoint != 'status' and endpoint != 'validators?per_page=100' and not re.fullmatch(r'block\?height=[0-9]+',endpoint):
        raise ValueError('Unsupported read endpoint')
    with OPENER.open('http://127.0.0.1:'+str(port)+'/'+endpoint, timeout=8) as response:
        raw = response.read(2000001)
    if len(raw)>2000000: raise ValueError('RPC response too large')
    return json.loads(raw)['result']

def identity(p):
    proc = Path('/proc')/str(p['pid'])
    return (proc/'stat').read_text().rsplit(')',1)[1].split()[19]

def alive(p):
    try:
        proc = Path('/proc')/str(p['pid'])
        stat = (proc/'stat').read_text().rsplit(')',1)[1].split()
        return stat[0] != 'Z' and stat[19] == p['start_ticks']
    except FileNotFoundError: return False

def verify(p):
    proc = Path('/proc')/str(p['pid'])
    args = (proc/'cmdline').read_bytes().decode().strip('\0').split('\0')
    if identity(p) != p['start_ticks'] or args != p['argv'] or str((proc/'exe').readlink()) != p['executable']:
        raise ValueError('Process identity changed; no signal sent')

def stop(p):
    verify(p)
    os.kill(p['pid'],signal.SIGTERM)
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        if not alive(p): return
        time.sleep(.25)
    raise RuntimeError('Graceful stop timeout. No forced kill. Inspect processes before continuing.')

def checkpoint(app):
    result=subprocess.run([app['executable'],'-info','-listen','tcp://127.0.0.1:29658'],
        stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=15,check=True)
    value=json.loads(result.stdout)
    if not isinstance(value.get('height'),int) or value['height']<1 or not re.fullmatch(r'[0-9a-fA-F]{64}',value.get('hash','')):
        raise ValueError('Invalid checkpoint')
    return {'height':value['height'],'hash':value['hash'].lower()}

def health():
    heights=[]
    for i in range(4):
        config=tomllib.loads((ROOT/('node'+str(i))/'config/config.toml').read_text())
        expected=29657+i*10
        if config['proxy_app'] != 'tcp://127.0.0.1:'+str(29658+i*10): raise ValueError('Unexpected application mapping')
        # Accept only explicitly local RPC listener configurations.
        if config['rpc']['laddr'] not in ('tcp://127.0.0.1:'+str(expected),'tcp://0.0.0.0:'+str(expected)):
            raise ValueError('Unexpected RPC mapping')
        status=rpc(expected,'status')
        if status['node_info']['network']!='voin-devnet-1' or status['sync_info']['catching_up'] is not False:
            raise ValueError('A node is not ready')
        heights.append(int(status['sync_info']['latest_block_height']))
    if max(heights)-min(heights)>5: raise ValueError('Nodes too far apart for this test')
    validators=rpc(29657,'validators?per_page=100')
    values=validators['validators']
    if int(validators['total'])!=4 or len(values)!=4 or any(int(v['voting_power'])!=1 for v in values):
        raise ValueError('Expected exactly four equal-power validators')
    old=heights[0]
    time.sleep(3)
    if int(rpc(29657,'status')['sync_info']['latest_block_height'])<=old:
        raise ValueError('No block progress observed; no restart allowed')
    return heights

def launch(p,args,log):
    return subprocess.Popen(args,executable=p['executable'],cwd=p['cwd'],stdin=subprocess.DEVNULL,
        stdout=log,stderr=subprocess.STDOUT,start_new_session=True)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--restart',action='store_true',help='Offer interactive consent after preflight')
    args=parser.parse_args()
    os.umask(0o077)
    spec=importlib.util.spec_from_file_location('voin_baseline',Path(__file__).with_name('voin_restart_check.py'))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    before=module.collect()
    apps=[p for p in before['processes'] if p['argv'][1:]==['-listen','tcp://127.0.0.1:29658','-state',str(ROOT/'state0.json')]]
    nodes=[p for p in before['processes'] if p['argv'][1:]==['node','--home',str(ROOT/'node0')]]
    if len(apps)!=1 or len(nodes)!=1: raise ValueError('Target process arguments differ; no restart allowed')
    app,node=apps[0],nodes[0]
    if Path(app['executable']).name!='voin-multinode-lab' or Path(node['executable']).name!='cometbft':
        raise ValueError('Unexpected executable')
    for p in (app,node): verify(p)
    heights=health()
    current=checkpoint(app)
    print('PREFLIGHT OK: 4 equal-power validators; all 4 RPC nodes respond; blocks advancing.',flush=True)
    print('TARGET: node0 + application state0.json ONLY; other processes untouched.',flush=True)
    print('HEIGHTS:',heights,'CHECKPOINT (provisional):',current['height'],flush=True)
    print('ALICE:',before['accounts']['alice']['balance'],before['accounts']['alice']['nonce'],
          'BOB:',before['accounts']['bob']['balance'],before['accounts']['bob']['nonce'],flush=True)
    if not args.restart:
        print('PLAN ONLY: no process stopped. Use --restart only when ready for a graceful restart.')
        return
    if not os.isatty(0): raise ValueError('Interactive terminal required')
    consent=input('Type RESTART NODE0 to stop/restart this pair; anything else cancels: ')
    if consent!='RESTART NODE0':
        print('Cancelled. No process stopped.')
        return
    # Recheck readiness and identities after consent, not only before the prompt.
    health()
    for p in (app,node): verify(p)
    before=module.collect()
    folder=Path.home()/'voin-restart-records'
    if folder.is_symlink(): raise ValueError('Records directory cannot be symlink')
    folder.mkdir(mode=0o700,exist_ok=True)
    if folder.stat().st_mode & 0o077: raise ValueError('Records directory must be private')
    import tempfile
    run=Path(tempfile.mkdtemp(prefix='controlled-',dir=folder))
    (run/'before.json').write_text(json.dumps(before,indent=2))
    print('LOGS:',run,flush=True)
    print('Stopping node0 gracefully...',flush=True)
    stop(node)
    trusted=checkpoint(app)
    time.sleep(1)
    if checkpoint(app)!=trusted: raise ValueError('Checkpoint advancing after node stop; app not stopped')
    # Compare disk with a live application checkpoint, not a disk-derived trust value.
    state=(ROOT/'state0.json').read_bytes()
    if hashlib.sha256(state).hexdigest()!=trusted['hash'] or json.loads(state)['height']!=trusted['height']:
        raise ValueError('Disk state does not match live checkpoint; app remains running')
    (run/'trusted-local-checkpoint.json').write_text(json.dumps(trusted,indent=2))
    newargs=app['argv']+['-checkpoint',trusted['hash']]
    (run/'recovery-commands.txt').write_text('Application (only if stopped):\n'+shlex.join(newargs)+'\nNode (only if stopped):\n'+shlex.join(node['argv'])+'\n')
    print('Stopping application gracefully...',flush=True)
    stop(app)
    with (run/'app.log').open('ab') as log:
        app_new=launch(app,newargs,log)
    deadline=time.monotonic()+25
    while True:
        if app_new.poll() is not None: raise RuntimeError('Application exited. Inspect app.log; no reset or retry performed.')
        try:
            restored=checkpoint(app)
            if restored!=trusted: raise ValueError('Restored checkpoint mismatch')
            break
        except (subprocess.SubprocessError,OSError):
            if time.monotonic()>deadline: raise RuntimeError('Application checkpoint unavailable; inspect app.log')
            time.sleep(.5)
    with (run/'node.log').open('ab') as log:
        node_new=launch(node,node['argv'],log)
    deadline=time.monotonic()+120
    while True:
        if app_new.poll() is not None or node_new.poll() is not None: raise RuntimeError('Restarted process exited; inspect logs')
        try:
            status=rpc(29657,'status')
            if int(status['sync_info']['latest_block_height'])>max(before['height'],trusted['height']) and status['sync_info']['catching_up'] is False:
                break
        except (OSError,ValueError,KeyError): pass
        if time.monotonic()>deadline: raise RuntimeError('Resume timeout; inspect logs. No automatic retry.')
        time.sleep(1)
    after=module.collect()
    if after['accounts']!=before['accounts']: raise ValueError('Accounts changed; inspect concurrent transfers, do not reset')
    committed=rpc(29657,'block?height='+str(trusted['height']+1))['block']['header']['app_hash'].lower()
    if committed!=trusted['hash']: raise ValueError('Checkpoint does not match resumed chain header')
    report={'result':'PASS','scope':'one-pair graceful restart only','checkpoint':trusted,'before':before,'after':after,
        'not_tested':['machine crash','power loss','independent checkpoint trust','production safety']}
    (run/'report.json').write_text(json.dumps(report,indent=2))
    print('PASS: same live checkpoint restored, chain advanced, Alice/Bob balances and nonces unchanged.',flush=True)
    print('PASS: checkpoint matches application hash in the next block. NOT a crash-safety or production audit.',flush=True)
    print('Restarted processes remain running. No transactions, genesis reset, key deletion, commit or push.',flush=True)

if __name__=='__main__':
    try: main()
    except KeyboardInterrupt:
        print('\nINTERRUPTED: if restart began, inspect processes and logs. Do not rerun blindly or reset data.')
        raise SystemExit(130)
    except Exception as exc:
        print('STOP:',exc)
        print('No forced kill or automatic reset. If a process was stopped, inspect logs/recovery commands before continuing.')
        raise SystemExit(1)
