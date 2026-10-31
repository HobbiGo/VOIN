#!/usr/bin/env python3
"""Persistent, local TEST devnet controller for Linux Codespaces.
Not production. Private runtime/key data is outside Git. Wallet keys unencrypted.
Commands: run (initialize once/start), status, stop, wallet [CLI flags].
Only clean shutdown has an automated restore path. Never auto-reset after a crash.
"""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path.home() / 'voin-private-devnet-01'
PORTS = [{'p2p':29656+i*10, 'rpc':29657+i*10, 'abci':29658+i*10} for i in range(4)]


def command(args, cwd, timeout=240):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Command failed: '+' '.join(map(str,args))+'\n'+(result.stdout+result.stderr)[-5000:])
    return result.stdout


def rpc(i, method, **params):
    url = 'http://127.0.0.1:%s/%s?%s' % (PORTS[i]['rpc'], method, urllib.parse.urlencode(params))
    try:
        with urllib.request.urlopen(url, timeout=4) as response:
            data = json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError('RPC HTTP %s: %s' % (error.code,error.read().decode()[:1200])) from error
    if 'error' in data: raise RuntimeError(str(data['error']))
    return data['result']


def atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.write-', dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(value,stream,indent=2)
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary,path)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def process_identity(pid):
    path=Path('/proc')/str(pid)
    try:
        stat=(path/'stat').read_text().rsplit(')',1)[1].split()
        if stat[0]=='Z': return None
        args=(path/'cmdline').read_bytes().split(b'\0')
        return {'pid':pid,'start_ticks':stat[19]},args
    except (FileNotFoundError,ProcessLookupError): return None


def alive(record, required):
    if not record: return False
    current=process_identity(record['pid'])
    if current is None: return False
    identity,args=current
    if identity['start_ticks'] != record['start_ticks']: return False
    if str(required).encode() not in args:
        raise RuntimeError('Recorded PID command does not match this devnet; refused to signal it')
    return True


def save(manifest): atomic_json(ROOT/'manifest.json',manifest)


def read_manifest():
    if not (ROOT/'manifest.json').is_file():
        raise RuntimeError('Devnet manifest not found. No existing directory will be reset automatically.')
    data=json.loads((ROOT/'manifest.json').read_text())
    if data.get('format')!=1: raise RuntimeError('Unsupported manifest')
    return data


def process_groups(manifest):
    result={}
    for i in range(4):
        for kind in ('app','node'):
            key=kind+str(i)
            required=ROOT/('state'+str(i)+'.json') if kind=='app' else ROOT/('node'+str(i))
            result[key]=alive(manifest['processes'].get(key),required)
    return result


def show_status(manifest):
    groups=process_groups(manifest)
    print('PRIVATE TEST DEVNET:',ROOT,flush=True)
    print('4 validators on ONE machine. No public ports or real assets.',flush=True)
    heights=[]
    for i in range(4):
        try:
            if not groups['node'+str(i)] or not groups['app'+str(i)]:
                raise RuntimeError('one or both recorded processes are stopped')
            status=rpc(i,'status')
            height=int(status['sync_info']['latest_block_height'])
            heights.append(height)
            print('node%s: RUNNING height=%s' % (i,height),flush=True)
        except Exception as error:
            print('node%s: %s' % (i,str(error)[:240]),flush=True)
    if len(heights)==4 and min(heights)>0:
        common=min(heights)
        hashes=[rpc(i,'block',height=common)['block_id']['hash'] for i in range(4)]
        if len(set(hashes))!=1: raise RuntimeError('Block hash disagreement')
        app_hashes=[rpc(i,'block',height=common)['block']['header']['app_hash'] for i in range(4)]
        if len(set(app_hashes))!=1: raise RuntimeError('Application hash disagreement')
        print('PASS: same block and application hash at common height',common,flush=True)
    print('Wallet names/addresses are in:',ROOT/'wallet-public.json',flush=True)
    print('Wallet keys are unencrypted TEST keys in $HOME/voin-test-wallets. Do not upload.',flush=True)
    return groups


def initialize(repo):
    if ROOT.exists(): return read_manifest()
    module=repo/'consensus/voin-app'
    print('RUN: source tests before creating devnet',flush=True)
    command(['go','test','-race','./...','-count=1','-timeout=120s'],module)
    command(['go','vet','./...'],module)
    command(['python','-m','unittest','discover','-s','tests'],repo)
    # Separate wallet command targets node0 of this devnet. Existing wallet unchanged.
    original=(module/'cmd/voin-test-wallet/main.go').read_text()
    marker='http://127.0.0.1:28657/'
    if original.count(marker)!=1: raise RuntimeError('Unexpected test wallet source')
    wallet_source=original.replace(marker,'http://127.0.0.1:29657/',1)
    target=module/'cmd/voin-private-wallet/main.go'
    if target.exists() and target.read_text()!=wallet_source:
        raise RuntimeError('Private wallet command has different edits; not overwritten')
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(wallet_source)
    # Reserve/check every intended port before initialization; do not stop other labs.
    for entry in PORTS:
        for port in entry.values():
            with socket.socket() as probe: probe.bind(('127.0.0.1',port))
    ROOT.mkdir(mode=0o700)
    (ROOT/'bin').mkdir(mode=0o700)
    comet_source=Path.home()/'voin-tools/bin/cometbft'
    if '1.0.1' not in command([str(comet_source),'version'],repo):
        raise RuntimeError('Expected CometBFT1.0.1; incomplete directory retained, not reset')
    import shutil
    shutil.copy2(comet_source,ROOT/'bin/cometbft')
    command(['go','build','-o',str(ROOT/'bin/voin-multinode-lab'),'./cmd/voin-multinode-lab'],module)
    command(['go','build','-o',str(ROOT/'bin/voin-private-wallet'),'./cmd/voin-private-wallet'],module)
    command(['go','test','-race','./...','-count=1','-timeout=120s'],module)
    suffix=str(time.time_ns())
    wallet=ROOT/'bin/voin-private-wallet'
    public={}
    for person in ('alice','bob'):
        name=person+'-private-devnet-'+suffix+'.json'
        value=json.loads(command([str(wallet),'-action','new','-wallet',name],repo,timeout=30))
        public[person]={'wallet':name,'address':value['address']}
    atomic_json(ROOT/'wallet-public.json',public)
    spec=importlib.util.spec_from_file_location('voin_persistent_helpers',repo/'docs/voin-transfer-package-20261031-1543.py')
    helper=importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
    comet=ROOT/'bin/cometbft'
    docs=[]; ids=[]
    for i in range(4):
        home=ROOT/('node'+str(i))
        command([str(comet),'init','--home',str(home)],repo,timeout=30)
        docs.append(json.loads((home/'config/genesis.json').read_text()))
        ids.append(command([str(comet),'show-node-id','--home',str(home)],repo,timeout=30).strip())
    validators=[]
    for document in docs:
        if len(document['validators'])!=1: raise RuntimeError('Unexpected initial validators')
        value=document['validators'][0]; value['power']='1'; validators.append(value)
    if len({v['address'] for v in validators})!=4: raise RuntimeError('Duplicate validators')
    genesis=docs[0]
    genesis.update(chain_id='voin-devnet-1',initial_height='1',app_hash='',validators=validators,
                   app_state=[[public['alice']['address'],'1000'],[public['bob']['address'],'1000']])
    genesis_text=json.dumps(genesis,indent=2)
    for i in range(4):
        home=ROOT/('node'+str(i))
        (home/'config/genesis.json').write_text(genesis_text)
        config_path=home/'config/config.toml'
        helper.patch_config(config_path)
        text=config_path.read_text()
        for kind,old in [('p2p',28656),('rpc',28657),('abci',28658)]:
            text=text.replace('tcp://127.0.0.1:'+str(old),'tcp://127.0.0.1:'+str(PORTS[i][kind]))
        peers=','.join(ids[j]+'@127.0.0.1:'+str(PORTS[j]['p2p']) for j in range(4) if j!=i)
        section=''; lines=[]
        for line in text.splitlines():
            if line.startswith('['): section=line.strip()
            if section=='[p2p]':
                for key,value in [('persistent_peers',json.dumps(peers)),('allow_duplicate_ip','true'),('addr_book_strict','false')]:
                    if re.match(r'^'+key+r'\s*=',line): line=key+' = '+value
            lines.append(line)
        config_path.write_text('\n'.join(lines)+'\n')
        import tomllib
        config=tomllib.loads(config_path.read_text())
        assert config['p2p']['allow_duplicate_ip'] is True
        assert config['p2p']['addr_book_strict'] is False
        assert config['proxy_app']=='tcp://127.0.0.1:'+str(PORTS[i]['abci'])
    manifest={'format':1,'chain_id':'voin-devnet-1','initialized_at':time.time(),
              'clean_shutdown':True,'processes':{},'checkpoints':{},
              'binary_source_commit':command(['git','rev-parse','HEAD'],repo).strip(),
              'genesis_sha256':hashlib.sha256(genesis_text.encode()).hexdigest()}
    save(manifest)
    print('Initialized ONCE: 4 local validators, 1000 TEST units each for Alice and Bob.',flush=True)
    return manifest


def start_devnet(manifest):
    groups=process_groups(manifest)
    if all(groups.values()):
        print('Already running; no duplicate processes created.',flush=True)
        return show_status(manifest)
    if any(groups.values()):
        raise RuntimeError('Partial running state. Use stop; no duplicate or automatic reset attempted.')
    if not manifest['clean_shutdown']:
        raise RuntimeError('Prior shutdown was unclean. Automatic start refused; recovery needs inspection.')
    for i in range(4):
        home=ROOT/('node'+str(i))
        if hashlib.sha256((home/'config/genesis.json').read_bytes()).hexdigest()!=manifest['genesis_sha256']:
            raise RuntimeError('Genesis changed; start refused')
        state=ROOT/('state'+str(i)+'.json')
        if state.exists():
            checkpoint=manifest['checkpoints'].get(str(i))
            raw=state.read_bytes()
            if not checkpoint or hashlib.sha256(raw).hexdigest()!=checkpoint['hash']:
                raise RuntimeError('Missing or mismatched trusted local checkpoint for app'+str(i))
            if json.loads(raw)['height']!=checkpoint['height']:
                raise RuntimeError('Checkpoint height mismatch')
        elif str(i) in manifest['checkpoints']:
            raise RuntimeError('Expected saved state is missing')
    for entry in PORTS:
        for port in entry.values():
            with socket.socket() as probe: probe.bind(('127.0.0.1',port))
    manifest['clean_shutdown']=False
    manifest['processes']={}; save(manifest)
    def launch(name,args):
        with (ROOT/(name+'.log')).open('ab') as log:
            p=subprocess.Popen(args,cwd=ROOT,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
        current=process_identity(p.pid)
        if current is None: raise RuntimeError('Process exited immediately: '+name)
        manifest['processes'][name]=current[0]; save(manifest)
    for i in range(4):
        args=[str(ROOT/'bin/voin-multinode-lab'),'-listen','tcp://127.0.0.1:'+str(PORTS[i]['abci']),
              '-state',str(ROOT/('state'+str(i)+'.json'))]
        if str(i) in manifest['checkpoints']: args+=['-checkpoint',manifest['checkpoints'][str(i)]['hash']]
        launch('app'+str(i),args)
    time.sleep(1)
    for i in range(4):
        launch('node'+str(i),[str(ROOT/'bin/cometbft'),'node','--home',str(ROOT/('node'+str(i)))])
    deadline=time.monotonic()+120
    initial=None; last='not ready'
    while time.monotonic()<deadline:
        if not all(process_groups(manifest).values()):
            raise RuntimeError('Process exited during startup. Inspect logs; no reset attempted.')
        try:
            heights=[int(rpc(i,'status')['sync_info']['latest_block_height']) for i in range(4)]
            if min(heights)>0:
                if initial is None: initial=min(heights)
                if min(heights)>initial:
                    show_status(manifest)
                    print('PRIVATE DEVNET RUNNING. Processes stay active after this command exits.',flush=True)
                    return
        except Exception as error: last=str(error)
        time.sleep(1)
    raise RuntimeError('Startup timeout; processes left for inspection. Use status/stop. '+last)


def stop_devnet(manifest):
    groups=process_groups(manifest)
    if not any(groups.values()) and manifest['clean_shutdown']:
        print('Already stopped cleanly. No data changed.',flush=True); return
    def terminate(name,required):
        record=manifest['processes'].get(name)
        if not alive(record,required): return
        os.kill(record['pid'],signal.SIGTERM)
        deadline=time.monotonic()+35
        while time.monotonic()<deadline:
            if not alive(record,required): return
            time.sleep(0.3)
        raise RuntimeError('Normal shutdown timed out for '+name+'; no forced kill performed')
    # First stop ALL consensus nodes. No app checkpoint is captured while any node advances.
    for i in range(4): terminate('node'+str(i),ROOT/('node'+str(i)))
    checkpoints={}
    for i in range(4):
        if not alive(manifest['processes'].get('app'+str(i)),ROOT/('state'+str(i)+'.json')):
            raise RuntimeError('App'+str(i)+' unavailable for live checkpoint. Unclean recovery requires inspection.')
        value=json.loads(command([str(ROOT/'bin/voin-multinode-lab'),'-listen',
            'tcp://127.0.0.1:'+str(PORTS[i]['abci']),'-info'],ROOT,timeout=20))
        raw=(ROOT/('state'+str(i)+'.json')).read_bytes()
        if value['hash']!=hashlib.sha256(raw).hexdigest() or value['height']!=json.loads(raw)['height']:
            raise RuntimeError('Live checkpoint differs from saved state at app'+str(i))
        checkpoints[str(i)]=value
    manifest['checkpoints']=checkpoints; save(manifest)
    for i in range(4): terminate('app'+str(i),ROOT/('state'+str(i)+'.json'))
    manifest['clean_shutdown']=True; manifest['processes']={}; save(manifest)
    print('PRIVATE DEVNET STOPPED CLEANLY. Same genesis, validator identities, balances retained.',flush=True)
    print('Local live-app checkpoints saved. These are not independent validator trust proofs.',flush=True)


def main():
    os.umask(0o077)
    action=sys.argv[1] if len(sys.argv)>1 else 'run'
    if action not in ('run','status','stop','wallet'):
        raise RuntimeError('Choose run, status, stop, or wallet [wallet CLI flags]')
    # Serialize operators with a private no-follow lock in the home directory.
    lock_path=Path.home()/'.voin-private-devnet-01.lock'
    fd=os.open(lock_path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if ROOT.is_symlink(): raise RuntimeError('Runtime root may not be a symlink')
        if ROOT.exists() and (not ROOT.is_dir() or ROOT.stat().st_mode&0o077):
            raise RuntimeError('Runtime root must be a private real0700 directory')
        repo=Path(subprocess.check_output(['git','rev-parse','--show-toplevel'],text=True).strip())
        if action=='run':
            if command(['git','branch','--show-current'],repo).strip()!='feature/signed-transfers':
                raise RuntimeError('Expected feature/signed-transfers')
            manifest=initialize(repo); start_devnet(manifest)
        else:
            manifest=read_manifest()
            if action=='status': show_status(manifest)
            elif action=='stop': stop_devnet(manifest)
            elif action=='wallet':
                result=subprocess.run([str(ROOT/'bin/voin-private-wallet'),*sys.argv[2:]],cwd=ROOT,timeout=30)
                if result.returncode: raise RuntimeError('Wallet command did not succeed')
        print('No git commit/push performed. Never upload runtime directories or wallet keys.',flush=True)


if __name__=='__main__':
    try: main()
    except KeyboardInterrupt:
        print('Controller interrupted. Devnet processes may remain active; use status/stop, never reset.')
        raise SystemExit(130)
    except Exception as error:
        print('PRIVATE DEVNET ACTION NOT COMPLETED:',error,flush=True)
        print('No automatic genesis reset. Inspect logs and status before retrying.',flush=True)
        raise SystemExit(1)
