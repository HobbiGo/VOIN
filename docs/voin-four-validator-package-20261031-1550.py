#!/usr/bin/env python3
"""Four local VOIN validators, independent application state per node.
Experimental localhost-only lab. Not four machines or production decentralization.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


def main():
    os.umask(0o077)
    repo = Path(subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip())
    spec = importlib.util.spec_from_file_location(
        'voin_lab_helpers', repo / 'docs/voin-transfer-package-20261031-1543.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    command = helper.command
    if command(['git', 'branch', '--show-current'], repo).strip() != 'feature/signed-transfers':
        raise RuntimeError('Expected branch feature/signed-transfers')
    module = repo / 'consensus/voin-app'
    comet = Path.home() / 'voin-tools/bin/cometbft'
    if '1.0.1' not in command([str(comet), 'version'], repo):
        raise RuntimeError('Expected CometBFT 1.0.1')
    ports = [{'p2p': 29656+i*10, 'rpc': 29657+i*10, 'abci': 29658+i*10} for i in range(4)]
    for entry in ports:
        for port in entry.values():
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', port))

    # A separate command leaves the tested single-validator server unchanged.
    source = (module / 'cmd/voin-transfer-lab/main.go').read_text()
    markers = ['flag.Parse()', 'abciserver.NewServer("tcp://127.0.0.1:28658", "socket", app)',
               'return readCheckpoint()', 'func readCheckpoint() error',
               'abciclient.NewClient("tcp://127.0.0.1:28658", "socket", true)']
    if any(source.count(marker) != 1 for marker in markers):
        raise RuntimeError('Unexpected transfer server source; no file overwritten')
    listeners = ', '.join('"tcp://127.0.0.1:%s": true' % p['abci'] for p in ports)
    replacement = '''listen := flag.String("listen", "tcp://127.0.0.1:29658", "fixed local lab address")
    flag.Parse()
    allowed := map[string]bool{LISTENERS}
    if !allowed[*listen] { return fmt.Errorf("address not permitted for local lab") }'''.replace('LISTENERS', listeners)
    source = source.replace('flag.Parse()', replacement, 1)
    source = source.replace(markers[1], 'abciserver.NewServer(*listen, "socket", app)', 1)
    source = source.replace(markers[2], 'return readCheckpoint(*listen)', 1)
    source = source.replace(markers[3], 'func readCheckpoint(address string) error', 1)
    source = source.replace(markers[4], 'abciclient.NewClient(address, "socket", true)', 1)
    formatted = subprocess.run(['gofmt'], input=source, text=True, capture_output=True,
                               check=True, timeout=30).stdout
    source_dir = module / 'cmd/voin-multinode-lab'
    source_dir.mkdir(exist_ok=True)
    target = source_dir / 'main.go'
    if target.exists() and target.read_text() != formatted:
        raise RuntimeError('Multinode server already has different edits; not overwritten')
    target.write_text(formatted)
    print('RUN: Go tests/race/vet and Python tests', flush=True)
    command(['go', 'test', '-race', './...', '-count=1', '-timeout=120s'], module)
    command(['go', 'vet', './...'], module)
    command(['python', '-m', 'unittest', 'discover', '-s', 'tests'], repo)
    print('PASS: source checks', flush=True)
    lab = Path(tempfile.mkdtemp(prefix='voin-four-validator-lab-', dir=Path.home()))
    binary = lab / 'voin-multinode-lab'
    command(['go', 'build', '-o', str(binary), './cmd/voin-multinode-lab'], module)
    print('LAB:', lab, flush=True)
    print('Four equal-power validators on ONE machine, localhost only.', flush=True)
    print('Do not forward ports or upload node directories/private keys.', flush=True)
    processes, logs = [], []
    nodes, apps = {}, {}
    homes = [lab / ('node'+str(i)) for i in range(4)]
    states = [lab / ('app'+str(i)+'.json') for i in range(4)]

    def rpc(i, method, **params):
        url = 'http://127.0.0.1:%s/%s?%s' % (
            ports[i]['rpc'], method, urllib.parse.urlencode(params))
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                data = json.load(response)
        except urllib.error.HTTPError as error:
            raise RuntimeError('RPC HTTP %s: %s' % (error.code, error.read().decode()[:1200])) from error
        if 'error' in data:
            raise RuntimeError(str(data['error']))
        return data['result']

    def height(i):
        return int(rpc(i, 'status')['sync_info']['latest_block_height'])

    def wait(action, active, timeout=100):
        deadline = time.monotonic()+timeout
        last = 'not ready'
        while time.monotonic() < deadline:
            if any(p.poll() is not None for p in active):
                raise RuntimeError('Lab process exited; inspect app/node logs')
            try:
                value = action()
                if value:
                    return value
            except Exception as error:
                last = str(error)
            time.sleep(0.7)
        raise RuntimeError('Wait timed out: '+last)

    def start(name, args):
        log = (lab / (name+'.log')).open('ab')
        logs.append(log)
        process = subprocess.Popen(args, cwd=repo, stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=log, start_new_session=True)
        processes.append(process)
        return process

    def stop(process):
        if process.poll() is not None:
            raise RuntimeError('Process already exited before controlled stop')
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=30)
        if process.returncode not in (0, -signal.SIGTERM):
            raise RuntimeError('Unclean process exit: '+str(process.returncode))

    def running(indices):
        return [p for i in indices for p in (apps[i], nodes[i])]

    def agreed_block(indices, minimum):
        if min(height(i) for i in indices) < minimum:
            return None
        hashes = [rpc(i, 'block', height=minimum)['block_id']['hash'] for i in indices]
        if len(set(hashes)) != 1:
            raise RuntimeError('Block hashes differ at height '+str(minimum))
        return hashes[0]

    def check_state_file(i, fixture):
        data = json.loads(states[i].read_bytes())
        a = data['accounts'][fixture['sender']]
        b = data['accounts'][fixture['recipient']]
        if (a['balance'], a['nonce'], b['balance']) != (750, 1, 250):
            raise RuntimeError('Incorrect balances/nonce at node '+str(i))
        return data

    try:
        fixture = json.loads(command([str(binary), '-fixture'], repo, timeout=30))
        (lab / 'fixture-public.json').write_text(json.dumps(fixture, indent=2))
        raw = json.dumps(fixture['transaction'], separators=(',', ':')).encode()
        genesis_docs, node_ids = [], []
        for i in range(4):
            command([str(comet), 'init', '--home', str(homes[i])], repo, timeout=30)
            genesis_docs.append(json.loads((homes[i]/'config/genesis.json').read_text()))
            node_ids.append(command([str(comet), 'show-node-id', '--home', str(homes[i])], repo, timeout=30).strip())
        validators = []
        for document in genesis_docs:
            if len(document['validators']) != 1:
                raise RuntimeError('Expected exactly one validator per fresh node')
            validator = document['validators'][0]
            validator['power'] = '1'
            validators.append(validator)
        if len({v['address'] for v in validators}) != 4:
            raise RuntimeError('Validator identities not distinct')
        genesis = genesis_docs[0]
        genesis.update(chain_id='voin-devnet-1', initial_height='1', app_hash='',
                       app_state=fixture['genesis'], validators=validators)
        canonical_genesis = json.dumps(genesis, indent=2)
        for i in range(4):
            (homes[i]/'config/genesis.json').write_text(canonical_genesis)
            config_path = homes[i]/'config/config.toml'
            helper.patch_config(config_path)
            text = config_path.read_text()
            text = text.replace('tcp://127.0.0.1:28658', 'tcp://127.0.0.1:'+str(ports[i]['abci']))
            text = text.replace('tcp://127.0.0.1:28657', 'tcp://127.0.0.1:'+str(ports[i]['rpc']))
            text = text.replace('tcp://127.0.0.1:28656', 'tcp://127.0.0.1:'+str(ports[i]['p2p']))
            peers = ','.join(node_ids[j]+'@127.0.0.1:'+str(ports[j]['p2p']) for j in range(4) if j != i)
            section, lines = '', []
            for line in text.splitlines():
                if line.startswith('['):
                    section = line.strip()
                if section == '[p2p]' and re.match(r'^persistent_peers\s*=', line):
                    line = 'persistent_peers = '+json.dumps(peers)
                if section == '[p2p]' and re.match(r'^allow_duplicate_ip\s*=', line):
                    line = 'allow_duplicate_ip = true'
                if section == '[p2p]' and re.match(r'^addr_book_strict\s*=', line):
                    line = 'addr_book_strict = false'
                lines.append(line)
            config_path.write_text('\n'.join(lines)+'\n')
            import tomllib
            config = tomllib.loads(config_path.read_text())
            assert config['p2p']['allow_duplicate_ip'] is True
            assert config['p2p']['addr_book_strict'] is False
            assert config['proxy_app'] == 'tcp://127.0.0.1:'+str(ports[i]['abci'])
            apps[i] = start('app'+str(i), [str(binary), '-listen', config['proxy_app'],
                                           '-state', str(states[i])])
        time.sleep(1)
        for i in range(4):
            nodes[i] = start('node'+str(i), [str(comet), 'node', '--home', str(homes[i])])
        wait(lambda: agreed_block(range(4), 2), running(range(4)), timeout=120)
        for i in range(4):
            info = rpc(i, 'validators', height=2)
            if int(info['total']) != 4 or len(info['validators']) != 4:
                raise RuntimeError('Validator set size differs')
            if any(int(v['voting_power']) != 1 for v in info['validators']):
                raise RuntimeError('Validator voting powers differ')
        print('PASS: four distinct validators, power 1 each, identical block at height 2', flush=True)
        submitted = rpc(0, 'broadcast_tx_sync', tx='0x'+raw.hex())
        if int(submitted.get('code', 0)) != 0:
            raise RuntimeError('Transfer rejected: '+str(submitted))
        tx_hash = hashlib.sha256(raw).hexdigest().upper()
        confirmed = wait(lambda: rpc(0, 'tx', hash='0x'+tx_hash, prove='false'), running(range(4)))
        if int(confirmed['tx_result'].get('code', 0)) != 0:
            raise RuntimeError('Transfer failed during block execution')
        tx_height = int(confirmed['height'])
        wait(lambda: agreed_block(range(4), tx_height+1), running(range(4)))
        state_hashes = []
        for i in range(4):
            block = rpc(i, 'block', height=tx_height)['block']
            if raw not in [base64.b64decode(v) for v in (block['data'].get('txs') or [])]:
                raise RuntimeError('Signed transfer absent at node '+str(i))
            result = rpc(i, 'tx', hash='0x'+tx_hash, prove='false')
            if int(result['tx_result'].get('code', 0)) != 0:
                raise RuntimeError('Transaction result differs')
            check_state_file(i, fixture)
            state_hashes.append(rpc(i, 'block', height=tx_height+1)['block']['header']['app_hash'])
        if len(set(state_hashes)) != 1:
            raise RuntimeError('Application hashes differ after transfer')
        print('PASS: signed transfer and matching post-transfer app hash on all four nodes', flush=True)
        print('PASS: all saved balances Alice=750 Bob=250 Alice nonce=1', flush=True)

        # Stop only validator node3; its app remains live, avoiding a checkpoint race.
        stop(nodes[3])
        baseline = max(height(i) for i in range(3))
        target_height = baseline+2
        outage_hash = wait(lambda: agreed_block(range(3), target_height), running(range(3)), timeout=120)
        print('PASS: three validators advance from', baseline, 'to', target_height,
              'with validator3 stopped', flush=True)
        nodes[3] = start('node3', [str(comet), 'node', '--home', str(homes[3])])
        caught_up_hash = wait(lambda: agreed_block(range(4), target_height), running(range(4)), timeout=120)
        if caught_up_hash != outage_hash:
            raise RuntimeError('Recovered node block differs')
        final_height = target_height+2
        wait(lambda: agreed_block(range(4), final_height), running(range(4)), timeout=120)
        for i in range(4):
            check_state_file(i, fixture)
        final_app_hashes = [rpc(i, 'block', height=final_height)['block']['header']['app_hash'] for i in range(4)]
        if len(set(final_app_hashes)) != 1:
            raise RuntimeError('Application hashes differ after catch-up')
        # Tie each captured on-disk state hash to that node's later block header.
        for i in range(4):
            captured = states[i].read_bytes()
            next_height = json.loads(captured)['height']+1
            wait(lambda i=i, h=next_height: height(i) >= h, running(range(4)))
            recorded = rpc(i, 'block', height=next_height)['block']['header']['app_hash']
            if recorded.upper() != hashlib.sha256(captured).hexdigest().upper():
                raise RuntimeError('Saved-state hash mismatch at node '+str(i))
        report = {'result': 'PASS', 'validators': 4, 'voting_power_each': 1,
                  'transaction_height': tx_height, 'transaction_hash': tx_hash,
                  'outage_baseline': baseline, 'outage_target': target_height,
                  'recovered_common_height': final_height,
                  'balances_each': {'alice': 750, 'bob': 250, 'alice_nonce': 1},
                  'scope': 'four localhost validators on one machine',
                  'not_tested': ['four separate hosts', 'malicious validators',
                                 'app3 restart', 'network partitions', 'crash safety',
                                 'performance', 'production security']}
        (lab/'result.json').write_text(json.dumps(report, indent=2))
        print('PASS: validator3 catches up without reset; all four continue', flush=True)
        print('PASS: saved state hashes confirmed by subsequent blocks', flush=True)
        print('FOUR VALIDATOR TRANSFER LAB PASS', flush=True)
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=25)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                    print('WARNING: forced lab cleanup; not a crash-safety success', flush=True)
        for log in logs:
            log.close()
        print('Private runtime/logs retained:', lab, flush=True)
        print('Old labs and single-validator server source unchanged. No commit/push.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted. Inspect logs before retrying.')
        raise SystemExit(130)
    except Exception as error:
        print('FOUR VALIDATOR TRANSFER LAB NOT PASSED:', error, flush=True)
        raise SystemExit(1)
