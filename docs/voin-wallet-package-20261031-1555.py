#!/usr/bin/env python3
"""Local experimental wallet package. Keys are NOT encrypted. No real funds."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

QUERY = r'''package voinapp

import (
    "context"
    "encoding/json"
    abci "github.com/cometbft/cometbft/abci/types"
)

// Query exposes a local committed account snapshot, NOT a Merkle proof.
func (app *TransferApp) Query(ctx context.Context, req *abci.QueryRequest) (*abci.QueryResponse, error) {
    if app == nil || app.App == nil || req == nil {
        return &abci.QueryResponse{Code: 1, Log: "missing application or request"}, nil
    }
    app.mu.Lock()
    defer app.mu.Unlock()
    if app.state == nil || req.Path != "/account" || req.Prove ||
        (req.Height != 0 && req.Height != app.state.Height) ||
        len(req.Data) != 69 || !accountPattern.Match(req.Data) {
        return &abci.QueryResponse{Code: 1, Log: "unsupported account query"}, nil
    }
    account, exists := app.state.Accounts[string(req.Data)]
    if !exists {
        return &abci.QueryResponse{Code: 1, Log: "account not found", Height: app.state.Height}, nil
    }
    value, err := json.Marshal(account)
    if err != nil { return nil, err }
    return &abci.QueryResponse{Code: 0, Height: app.state.Height,
        Key: append([]byte(nil), req.Data...), Value: value}, nil
}
'''

QUERY_TEST = r'''package voinapp

import (
    "context"
    "encoding/json"
    "testing"
    abci "github.com/cometbft/cometbft/abci/types"
)

func TestTransferAccountQuery(t *testing.T) {
    state, envelope, _ := testTransferFixture(t)
    app, err := NewTransferApp(&App{state: state})
    if err != nil { t.Fatal(err) }
    req := &abci.QueryRequest{Path: "/account", Data: []byte(envelope.Transfer.Sender)}
    result, err := app.Query(context.Background(), req)
    if err != nil || result.Code != 0 { t.Fatal("account query failed") }
    var account Account
    if err := json.Unmarshal(result.Value, &account); err != nil { t.Fatal(err) }
    if account.Balance != 1000 || account.Nonce != 0 { t.Fatal("wrong account") }
    req.Prove = true
    result, err = app.Query(context.Background(), req)
    if err != nil || result.Code == 0 { t.Fatal("unavailable proof was not rejected") }
    req.Prove = false
    req.Data = []byte(envelope.Transfer.Recipient)
    result, err = app.Query(context.Background(), req)
    if err != nil || result.Code == 0 { t.Fatal("missing account was not rejected") }
}
'''

WALLET = r'''// Experimental Linux-only local test wallet. Private keys are NOT encrypted.
package main

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "path/filepath"
    "regexp"
    "strings"
    "syscall"
    "time"
    voin "example.com/voin/abci"
    "github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

type walletFile struct {
    Version int `json:"version"`
    Address string `json:"address"`
    PublicKey string `json:"public_key"`
    PrivateKey string `json:"private_key"`
}
var addressPattern = regexp.MustCompile(`^voin_[0-9a-f]{64}$`)
var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}$`)

func main() {
    if err := run(); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}
func output(value interface{}) error { return json.NewEncoder(os.Stdout).Encode(value) }
func keyPath(name string) (string, error) {
    if !namePattern.MatchString(name) { return "", errors.New("invalid wallet filename") }
    home, err := os.UserHomeDir()
    if err != nil { return "", err }
    dir := filepath.Join(home, "voin-test-wallets")
    if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) { return "", err }
    info, err := os.Lstat(dir)
    if err != nil { return "", err }
    if !info.IsDir() || info.Mode().Perm() & 0077 != 0 {
        return "", errors.New("wallet directory must be a private real directory (0700)")
    }
    return filepath.Join(dir, name), nil
}
func newWallet(name string) error {
    path, err := keyPath(name)
    if err != nil { return err }
    pk, sk, err := mldsa44.GenerateKey(rand.Reader)
    if err != nil { return err }
    public, err := pk.MarshalBinary()
    if err != nil { return err }
    private, err := sk.MarshalBinary()
    if err != nil { return err }
    digest := sha256.Sum256(public)
    wallet := walletFile{1, "voin_"+hex.EncodeToString(digest[:]),
        hex.EncodeToString(public), hex.EncodeToString(private)}
    data, err := json.Marshal(wallet)
    if err != nil { return err }
    file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
    if err != nil { return err }
    if _, err := file.Write(data); err != nil { file.Close(); return err }
    if err := file.Sync(); err != nil { file.Close(); return err }
    if err := file.Close(); err != nil { return err }
    return output(map[string]interface{}{"address": wallet.Address, "wallet": name,
        "warning": "UNENCRYPTED TEST KEY; never use real assets or upload key files"})
}
func readWallet(name string) (*walletFile, *mldsa44.PrivateKey, error) {
    path, err := keyPath(name)
    if err != nil { return nil, nil, err }
    fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
    if err != nil { return nil, nil, err }
    file := os.NewFile(uintptr(fd), path)
    defer file.Close()
    info, err := file.Stat()
    if err != nil { return nil, nil, err }
    if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 20000 {
        return nil, nil, errors.New("wallet must be a small regular 0600 file")
    }
    data, err := io.ReadAll(io.LimitReader(file, 20001))
    if err != nil { return nil, nil, err }
    var wallet walletFile
    if err := json.Unmarshal(data, &wallet); err != nil { return nil, nil, err }
    public, err := hex.DecodeString(wallet.PublicKey)
    if err != nil || len(public) != mldsa44.PublicKeySize || wallet.Version != 1 {
        return nil, nil, errors.New("invalid test wallet")
    }
    digest := sha256.Sum256(public)
    if wallet.Address != "voin_"+hex.EncodeToString(digest[:]) {
        return nil, nil, errors.New("wallet address mismatch")
    }
    secret, err := hex.DecodeString(wallet.PrivateKey)
    if err != nil { return nil, nil, errors.New("invalid private key encoding") }
    var key mldsa44.PrivateKey
    if err := key.UnmarshalBinary(secret); err != nil { return nil, nil, errors.New("invalid private key") }
    return &wallet, &key, nil
}
func rpc(method string, params url.Values) (json.RawMessage, error) {
    client := &http.Client{Timeout: 10*time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return errors.New("redirect refused")
        }}
    response, err := client.Get("http://127.0.0.1:28657/"+method+"?"+params.Encode())
    if err != nil { return nil, err }
    defer response.Body.Close()
    body, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
    if err != nil { return nil, err }
    if len(body) > 1024*1024 { return nil, errors.New("RPC response too large") }
    if response.StatusCode != 200 { return nil, fmt.Errorf("RPC HTTP %d: %.1000s", response.StatusCode, body) }
    var envelope struct { Result json.RawMessage `json:"result"`; Error json.RawMessage `json:"error"` }
    if err := json.Unmarshal(body, &envelope); err != nil { return nil, err }
    if len(envelope.Error) != 0 && string(envelope.Error) != "null" {
        return nil, fmt.Errorf("RPC error: %.1000s", envelope.Error)
    }
    if len(envelope.Result) == 0 { return nil, errors.New("missing RPC result") }
    return envelope.Result, nil
}
func account(address string) (voin.Account, string, error) {
    var zero voin.Account
    if !addressPattern.MatchString(address) { return zero, "", errors.New("invalid address") }
    raw, err := rpc("abci_query", url.Values{"path": {`"/account"`},
        "data": {"0x"+hex.EncodeToString([]byte(address))}, "prove": {"false"}})
    if err != nil { return zero, "", err }
    var result struct { Response struct {
        Code uint32 `json:"code"`; Log string `json:"log"`
        Value string `json:"value"`; Height string `json:"height"`
    } `json:"response"` }
    if err := json.Unmarshal(raw, &result); err != nil { return zero, "", err }
    if result.Response.Code != 0 { return zero, "", errors.New(result.Response.Log) }
    value, err := base64.StdEncoding.DecodeString(result.Response.Value)
    if err != nil { return zero, "", err }
    if err := json.Unmarshal(value, &zero); err != nil { return zero, "", err }
    return zero, result.Response.Height, nil
}
func run() error {
    action := flag.String("action", "", "new, balance, send, status")
    name := flag.String("wallet", "", "basename in $HOME/voin-test-wallets")
    address := flag.String("address", "", "account address")
    to := flag.String("to", "", "recipient address")
    amount := flag.Uint64("amount", 0, "test units")
    hash := flag.String("hash", "", "transaction hash")
    flag.Parse()
    switch *action {
    case "new": return newWallet(*name)
    case "balance":
        value, height, err := account(*address)
        if err != nil { return err }
        return output(map[string]interface{}{"address": *address, "balance": value.Balance,
            "nonce": value.Nonce, "height": height, "proof_verified": false})
    case "send":
        wallet, sk, err := readWallet(*name)
        if err != nil { return err }
        value, _, err := account(wallet.Address)
        if err != nil { return err }
        if value.Nonce == ^uint64(0) || *amount == 0 || *amount > value.Balance {
            return errors.New("invalid amount, balance or nonce")
        }
        tx := voin.Transfer{Version: 1, ChainID: voin.ChainID, Sender: wallet.Address,
            Recipient: *to, Amount: *amount, Nonce: value.Nonce+1}
        message, err := json.Marshal(tx)
        if err != nil { return err }
        sig := make([]byte, mldsa44.SignatureSize)
        if err := mldsa44.SignTo(sk, message, []byte("VOIN/transfer/v1"), false, sig); err != nil { return err }
        raw, err := json.Marshal(voin.SignedTransfer{Transfer: tx,
            PublicKey: wallet.PublicKey, Signature: hex.EncodeToString(sig)})
        if err != nil { return err }
        if _, err := voin.VerifyTransfer(raw); err != nil { return err }
        submitted, err := rpc("broadcast_tx_sync", url.Values{"tx": {"0x"+hex.EncodeToString(raw)}})
        if err != nil { return err }
        var result struct { Code uint32 `json:"code"`; Log string `json:"log"` }
        if err := json.Unmarshal(submitted, &result); err != nil { return err }
        if result.Code != 0 { return errors.New(result.Log) }
        digest := sha256.Sum256(raw)
        return output(map[string]interface{}{"hash": strings.ToUpper(hex.EncodeToString(digest[:])),
            "status": "submitted_not_confirmed", "nonce": tx.Nonce})
    case "status":
        decoded, err := hex.DecodeString(*hash)
        if err != nil || len(decoded) != 32 { return errors.New("invalid transaction hash") }
        raw, err := rpc("tx", url.Values{"hash": {"0x"+hex.EncodeToString(decoded)}, "prove": {"false"}})
        if err != nil { return err }
        var result struct { Height string `json:"height"`; TxResult struct {
            Code uint32 `json:"code"`
        } `json:"tx_result"` }
        if err := json.Unmarshal(raw, &result); err != nil { return err }
        return output(map[string]interface{}{"hash": strings.ToUpper(*hash), "height": result.Height,
            "code": result.TxResult.Code, "proof_verified": false})
    default: return errors.New("choose -action new, balance, send or status")
    }
}
'''


def main():
    os.umask(0o077)
    repo = Path(subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip())
    spec = importlib.util.spec_from_file_location('voin_wallet_helpers', repo/'docs/voin-transfer-package-20261031-1543.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    command, rpc, wait = helper.command, helper.rpc, helper.wait_for
    if command(['git', 'branch', '--show-current'], repo).strip() != 'feature/signed-transfers':
        raise RuntimeError('Expected feature/signed-transfers')
    module = repo/'consensus/voin-app'
    files = {'transfer_query.go': QUERY, 'transfer_query_test.go': QUERY_TEST,
             'cmd/voin-test-wallet/main.go': WALLET}
    for name, content in files.items():
        formatted = subprocess.run(['gofmt'], input=content, text=True,
                                   capture_output=True, timeout=30, check=True).stdout
        target = module/name
        if target.exists() and target.read_text() != formatted:
            raise RuntimeError('Existing file differs; not overwritten: '+name)
    for name, content in files.items():
        target = module/name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(subprocess.run(['gofmt'], input=content, text=True,
            capture_output=True, timeout=30, check=True).stdout)
    print('RUN: source checks', flush=True)
    command(['go', 'test', '-race', './...', '-count=1', '-timeout=120s'], module)
    command(['go', 'vet', './...'], module)
    command(['python', '-m', 'unittest', 'discover', '-s', 'tests'], repo)
    print('PASS: source checks including account query test', flush=True)
    for port in (28656, 28657, 28658):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', port))
    lab = Path(tempfile.mkdtemp(prefix='voin-wallet-lab-', dir=Path.home()))
    wallet = lab/'voin-test-wallet'
    server = lab/'voin-transfer-lab'
    command(['go', 'build', '-o', str(wallet), './cmd/voin-test-wallet'], module)
    command(['go', 'build', '-o', str(server), './cmd/voin-transfer-lab'], module)
    comet = Path.home()/'voin-tools/bin/cometbft'
    if '1.0.1' not in command([str(comet), 'version'], repo):
        raise RuntimeError('Expected CometBFT 1.0.1')
    processes, logs = [], []
    print('LAB:', lab, flush=True)
    print('WARNING: unencrypted TEST keys under $HOME/voin-test-wallets; never upload them.', flush=True)
    try:
        suffix = lab.name.removeprefix('voin-wallet-lab-')
        alice_name, bob_name = 'alice-'+suffix+'.json', 'bob-'+suffix+'.json'
        def cli(*args):
            return json.loads(command([str(wallet), *args], repo, timeout=20))
        alice = cli('-action', 'new', '-wallet', alice_name)
        bob = cli('-action', 'new', '-wallet', bob_name)
        public = {'alice_address': alice['address'], 'bob_address': bob['address'],
                  'alice_wallet_name': alice_name, 'bob_wallet_name': bob_name}
        (lab/'wallet-public.json').write_text(json.dumps(public, indent=2))
        home = lab/'node'
        command([str(comet), 'init', '--home', str(home)], repo, timeout=30)
        path = home/'config/genesis.json'
        genesis = json.loads(path.read_text())
        genesis.update(chain_id='voin-devnet-1', initial_height='1', app_hash='',
                       app_state=[[alice['address'], '1000']])
        path.write_text(json.dumps(genesis, indent=2))
        helper.patch_config(home/'config/config.toml')
        for name, args in [('app', [str(server), '-state', str(lab/'state.json')]),
                           ('node', [str(comet), 'node', '--home', str(home)])]:
            log = (lab/(name+'.log')).open('ab')
            logs.append(log)
            p = subprocess.Popen(args, cwd=repo, stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=log, start_new_session=True)
            processes.append(p)
            if name == 'app': time.sleep(1)
        wait(lambda: int(rpc('status')['sync_info']['latest_block_height']) >= 1, processes)
        initial = cli('-action', 'balance', '-address', alice['address'])
        if initial['balance'] != 1000 or initial['nonce'] != 0:
            raise RuntimeError('Initial account query incorrect')
        sent = cli('-action', 'send', '-wallet', alice_name, '-to', bob['address'], '-amount', '250')
        confirmed = wait(lambda: cli('-action', 'status', '-hash', sent['hash']), processes)
        if confirmed['code'] != 0:
            raise RuntimeError('Wallet transaction execution failed')
        a = cli('-action', 'balance', '-address', alice['address'])
        b = cli('-action', 'balance', '-address', bob['address'])
        if (a['balance'], a['nonce'], b['balance']) != (750, 1, 250):
            raise RuntimeError('Wallet balance queries incorrect')
        # A second legitimate spend checks that the wallet obtains the updated nonce.
        sent2 = cli('-action', 'send', '-wallet', alice_name, '-to', bob['address'], '-amount', '50')
        confirmed2 = wait(lambda: cli('-action', 'status', '-hash', sent2['hash']), processes)
        if confirmed2['code'] != 0 or sent2['nonce'] != 2:
            raise RuntimeError('Second wallet transaction failed')
        a = cli('-action', 'balance', '-address', alice['address'])
        b = cli('-action', 'balance', '-address', bob['address'])
        if (a['balance'], a['nonce'], b['balance']) != (700, 2, 300):
            raise RuntimeError('Final wallet balances incorrect')
        invalid = subprocess.run([str(wallet), '-action', 'send', '-wallet', alice_name,
            '-to', bob['address'], '-amount', '701'], cwd=repo, capture_output=True, text=True, timeout=20)
        if invalid.returncode == 0 or 'invalid amount, balance or nonce' not in invalid.stderr:
            raise RuntimeError('Insufficient-balance spend not rejected as expected')
        unchanged = cli('-action', 'balance', '-address', alice['address'])
        if (unchanged['balance'], unchanged['nonce']) != (700, 2):
            raise RuntimeError('Rejected wallet spend changed account')
        report = {'result': 'PASS', 'scope': 'Linux localhost test-wallet CLI',
                  'alice_balance': 700, 'bob_balance': 300, 'alice_nonce': 2,
                  'transaction_hashes': [sent['hash'], sent2['hash']],
                  'keys_encrypted': False, 'query_proofs_verified': False,
                  'not_tested': ['encrypted storage', 'key recovery', 'hardware wallet',
                                 'remote untrusted RPC', 'production funds']}
        (lab/'result.json').write_text(json.dumps(report, indent=2))
        print('PASS: test wallets created; private keys not printed or put in repository', flush=True)
        print('PASS: wallet sends 250 then 50; both transactions confirmed', flush=True)
        print('PASS: account queries Alice=700 Bob=300 Alice nonce=2', flush=True)
        print('PASS: insufficient-balance spend rejected', flush=True)
        print('TEST WALLET LAB PASS', flush=True)
    finally:
        for p in reversed(processes):
            if p.poll() is None:
                p.terminate()
                try: p.wait(timeout=25)
                except subprocess.TimeoutExpired:
                    p.kill(); p.wait(timeout=10)
                    print('WARNING: forced lab cleanup', flush=True)
        for log in logs: log.close()
        print('Private runtime/logs retained:', lab, flush=True)
        print('Unencrypted test keys remain in $HOME/voin-test-wallets. Do not upload them.', flush=True)
        print('Only this lab stopped. Source files remain for review. No commit/push.', flush=True)


if __name__ == '__main__':
    try: main()
    except KeyboardInterrupt:
        print('Interrupted; inspect local logs before retrying.')
        raise SystemExit(130)
    except Exception as error:
        print('TEST WALLET LAB NOT PASSED:', error, flush=True)
        raise SystemExit(1)
