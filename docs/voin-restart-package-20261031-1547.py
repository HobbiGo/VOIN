#!/usr/bin/env python3
"""Controlled single-validator transfer restart. Experimental, no real assets."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


def main():
    os.umask(0o077)
    repo = Path(subprocess.check_output(
        ['git', 'rev-parse', '--show-toplevel'], text=True).strip())
    package = repo / 'docs/voin-transfer-package-20261031-1543.py'
    if not package.is_file():
        raise RuntimeError('Prior transfer package not found in docs')
    spec = importlib.util.spec_from_file_location('voin_previous_lab', package)
    prior = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prior)
    command, rpc, wait_for = prior.command, prior.rpc, prior.wait_for
    if command(['git', 'branch', '--show-current'], repo).strip() != 'feature/signed-transfers':
        raise RuntimeError('Expected branch feature/signed-transfers')
    module = repo / 'consensus/voin-app'
    source_path = module / 'cmd/voin-transfer-lab/main.go'
    original = prior.GO_SOURCE
    updated = original.replace('"syscall"', '''"syscall"
    "time"
    abciclient "github.com/cometbft/cometbft/abci/client"
    abci "github.com/cometbft/cometbft/abci/types"''', 1)
    updated = updated.replace('    flag.Parse()', '''    checkpoint := flag.String("checkpoint", "", "trusted checkpoint hash for restore")
    info := flag.Bool("info", false, "read local live ABCI checkpoint")
    flag.Parse()
    if *info { return readCheckpoint() }''', 1)
    old_constructor = '''    base, err := voin.NewFreshPersistentApp(*state)
    if err != nil { return err }'''
    new_constructor = '''    var base *voin.App
    var err error
    if *checkpoint == "" {
        base, err = voin.NewFreshPersistentApp(*state)
    } else {
        decoded, parseErr := hex.DecodeString(*checkpoint)
        if parseErr != nil || len(decoded) != 32 {
            return fmt.Errorf("checkpoint must be 32 bytes of hex")
        }
        var trusted [32]byte
        copy(trusted[:], decoded)
        base, err = voin.NewAppFromCheckpoint(*state, trusted)
    }
    if err != nil { return err }'''
    if old_constructor not in updated:
        raise RuntimeError('Prior server source shape differs; no source written')
    updated = updated.replace(old_constructor, new_constructor, 1)
    updated += '''
func readCheckpoint() error {
    client, err := abciclient.NewClient("tcp://127.0.0.1:28658", "socket", true)
    if err != nil { return err }
    if err := client.Start(); err != nil { return err }
    defer client.Stop()
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    info, err := client.Info(ctx, &abci.InfoRequest{})
    if err != nil { return err }
    if info == nil || info.LastBlockHeight < 1 || len(info.LastBlockAppHash) != 32 {
        return fmt.Errorf("no valid committed checkpoint")
    }
    return json.NewEncoder(os.Stdout).Encode(struct {
        Height int64 `json:"height"`
        Hash string `json:"hash"`
    }{info.LastBlockHeight, hex.EncodeToString(info.LastBlockAppHash)})
}
'''

    def formatted(source):
        return subprocess.run(['gofmt'], input=source, text=True,
                              capture_output=True, timeout=30, check=True).stdout

    proposed = formatted(updated)
    existing = formatted(source_path.read_text())
    if existing not in (formatted(original), proposed):
        raise RuntimeError('Server has other edits; refused to overwrite')
    # Install only after verifying the existing source matches the known previous package.
    source_path.write_text(proposed)
    print('RUN: tests/race/vet before any lab starts', flush=True)
    command(['go', 'test', '-race', './...', '-count=1', '-timeout=120s'], module)
    command(['go', 'vet', './...'], module)
    command(['python', '-m', 'unittest', 'discover', '-s', 'tests'], repo)
    print('PASS: source checks', flush=True)
    comet = Path.home() / 'voin-tools/bin/cometbft'
    if '1.0.1' not in command([str(comet), 'version'], repo):
        raise RuntimeError('Expected CometBFT 1.0.1')
    import socket
    for port in (28656, 28657, 28658):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', port))
    lab = Path(tempfile.mkdtemp(prefix='voin-restart-lab-', dir=Path.home()))
    binary = lab / 'voin-transfer-lab'
    processes, logs = [], []
    print('LAB:', lab, flush=True)

    def start(name, args):
        log = (lab / (name + '.log')).open('ab')
        logs.append(log)
        process = subprocess.Popen(args, cwd=repo, stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=log, start_new_session=True)
        processes.append(process)
        return process

    def stop(process):
        if process.poll() is not None:
            raise RuntimeError('Process exited before controlled shutdown')
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=25)
        if process.returncode not in (0, -signal.SIGTERM):
            raise RuntimeError('Unclean process exit: ' + str(process.returncode))

    def checkpoint():
        return json.loads(command([str(binary), '-info'], repo, timeout=20))

    def height():
        return int(rpc('status')['sync_info']['latest_block_height'])

    def state_balances(fixture):
        state = json.loads((lab / 'state.json').read_bytes())
        alice = state['accounts'][fixture['sender']]
        bob = state['accounts'][fixture['recipient']]
        if alice['balance'] != 750 or alice['nonce'] != 1 or bob['balance'] != 250:
            raise RuntimeError('Balances or nonce differ from committed transfer')
        return state

    try:
        command(['go', 'build', '-o', str(binary), './cmd/voin-transfer-lab'], module)
        fixture = json.loads(command([str(binary), '-fixture'], repo, timeout=30))
        (lab / 'fixture-public.json').write_text(json.dumps(fixture, indent=2))
        raw = json.dumps(fixture['transaction'], separators=(',', ':')).encode()
        home = lab / 'node'
        command([str(comet), 'init', '--home', str(home)], repo, timeout=30)
        genesis_path = home / 'config/genesis.json'
        genesis = json.loads(genesis_path.read_text())
        genesis.update(chain_id='voin-devnet-1', initial_height='1', app_hash='',
                       app_state=fixture['genesis'])
        genesis_path.write_text(json.dumps(genesis, indent=2))
        prior.patch_config(home / 'config/config.toml')
        app = start('app', [str(binary), '-state', str(lab / 'state.json')])
        time.sleep(1)
        node = start('node', [str(comet), 'node', '--home', str(home)])
        wait_for(lambda: height() >= 1, [app, node])
        response = rpc('broadcast_tx_sync', tx='0x' + raw.hex())
        if int(response.get('code', 0)) != 0:
            raise RuntimeError('Initial transfer rejected: ' + str(response))
        tx_hash = hashlib.sha256(raw).hexdigest().upper()
        confirmed = wait_for(lambda: rpc('tx', hash='0x' + tx_hash, prove='false'), [app, node])
        if int(confirmed['tx_result'].get('code', 0)) != 0:
            raise RuntimeError('Initial transfer execution failed')
        tx_height = int(confirmed['height'])
        block = rpc('block', height=tx_height)['block']
        if raw not in [base64.b64decode(v) for v in (block['data'].get('txs') or [])]:
            raise RuntimeError('Signed transaction missing from block')
        wait_for(lambda: state_balances(fixture), [app, node])
        print('PASS: signed transfer committed before restart', flush=True)

        stop(node)
        trusted = checkpoint()  # Live app, no advancing node; not a hash derived from disk.
        captured = (lab / 'state.json').read_bytes()
        if hashlib.sha256(captured).hexdigest() != trusted['hash']:
            raise RuntimeError('Disk hash differs from live application checkpoint')
        if json.loads(captured)['height'] != trusted['height']:
            raise RuntimeError('Checkpoint height mismatch')
        (lab / 'trusted-local-checkpoint.json').write_text(json.dumps(trusted, indent=2))
        stop(app)
        print('PASS: node then app stopped normally at height', trusted['height'], flush=True)

        app = start('app', [str(binary), '-state', str(lab / 'state.json'),
                            '-checkpoint', trusted['hash']])
        restored = wait_for(checkpoint, [app], timeout=30)
        if restored != trusted:
            raise RuntimeError('Restored checkpoint differs')
        state_balances(fixture)
        print('PASS: same committed checkpoint restored', flush=True)
        node = start('node', [str(comet), 'node', '--home', str(home)])
        first = wait_for(lambda: height() if height() > trusted['height'] else None, [app, node])
        wait_for(lambda: height() > first, [app, node])
        state_balances(fixture)
        print('PASS: existing node resumes blocks without reset', flush=True)

        # Require the exact application nonce rejection. HTTP 500 alone is not a pass.
        replay_rejected = False
        try:
            replay = rpc('broadcast_tx_sync', tx='0x' + raw.hex())
            replay_rejected = (int(replay.get('code', 0)) == 1 and
                               'invalid or exhausted nonce' in replay.get('log', ''))
        except RuntimeError as error:
            text = str(error)
            replay_rejected = ('invalid or exhausted nonce' in text and
                               ('code=1' in text or 'code: 1' in text or 'code:1' in text))
        if not replay_rejected:
            raise RuntimeError('Replay did not produce the expected application nonce rejection')
        later = height()
        wait_for(lambda: height() > later, [app, node])
        state_balances(fixture)
        captured = (lab / 'state.json').read_bytes()
        target = json.loads(captured)['height'] + 1
        wait_for(lambda: height() >= target, [app, node])
        recorded = rpc('block', height=target)['block']['header']['app_hash']
        if recorded.upper() != hashlib.sha256(captured).hexdigest().upper():
            raise RuntimeError('Post-restart state hash not confirmed in next block')
        print('PASS: replay rejected; balances and nonce unchanged', flush=True)
        print('PASS: post-restart state hash matches next block', flush=True)
        report = {'result': 'PASS', 'trusted_local_checkpoint_height': trusted['height'],
                  'first_resumed_height': first, 'transaction_height': tx_height,
                  'sender_balance': 750, 'recipient_balance': 250, 'sender_nonce': 1,
                  'replay_rejected': True, 'scope': 'graceful restart, one local validator',
                  'not_tested': ['machine crash', 'independent checkpoint trust',
                                 'multi-validator transfers', 'performance', 'production safety']}
        (lab / 'result.json').write_text(json.dumps(report, indent=2))
        print('TRANSFER RESTART LAB PASS', flush=True)
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=25)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                    print('WARNING: cleanup forced a stop; not a crash-safety success', flush=True)
        for log in logs:
            log.close()
        print('Private data/logs kept:', lab, flush=True)
        print('Old labs untouched. No git commit/push. Server source changes remain for review.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted. Inspect logs before retrying.')
        raise SystemExit(130)
    except Exception as error:
        print('TRANSFER RESTART LAB NOT PASSED:', error, flush=True)
        raise SystemExit(1)
