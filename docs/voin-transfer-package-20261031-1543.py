#!/usr/bin/env python3
"""Experimental local VOIN transfer lab; no real assets or automatic git writes."""
import base64
import hashlib
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

GO_SOURCE = r'''package main

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "os/signal"
    "syscall"

    voin "example.com/voin/abci"
    abciserver "github.com/cometbft/cometbft/abci/server"
    "github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

func main() {
    if err := run(); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}

func run() error {
    fixture := flag.Bool("fixture", false, "emit public test fixture; private keys stay in memory")
    state := flag.String("state", "", "absolute fresh state file")
    flag.Parse()
    if *fixture { return makeFixture() }
    base, err := voin.NewFreshPersistentApp(*state)
    if err != nil { return err }
    app, err := voin.NewTransferApp(base)
    if err != nil { return err }
    server, err := abciserver.NewServer("tcp://127.0.0.1:28658", "socket", app)
    if err != nil { return err }
    if err := server.Start(); err != nil { return err }
    ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer cancel()
    <-ctx.Done()
    return server.Stop()
}

func makeFixture() error {
    pk, sk, err := mldsa44.GenerateKey(rand.Reader)
    if err != nil { return err }
    bob, _, err := mldsa44.GenerateKey(rand.Reader)
    if err != nil { return err }
    public, err := pk.MarshalBinary()
    if err != nil { return err }
    recipientPublic, err := bob.MarshalBinary()
    if err != nil { return err }
    a := sha256.Sum256(public)
    b := sha256.Sum256(recipientPublic)
    sender := "voin_" + hex.EncodeToString(a[:])
    recipient := "voin_" + hex.EncodeToString(b[:])
    tx := voin.Transfer{Version: 1, ChainID: voin.ChainID,
        Sender: sender, Recipient: recipient, Amount: 250, Nonce: 1}
    message, err := json.Marshal(tx)
    if err != nil { return err }
    sig := make([]byte, mldsa44.SignatureSize)
    if err := mldsa44.SignTo(sk, message, []byte("VOIN/transfer/v1"), false, sig); err != nil {
        return err
    }
    envelope := voin.SignedTransfer{Transfer: tx,
        PublicKey: hex.EncodeToString(public), Signature: hex.EncodeToString(sig)}
    raw, err := json.Marshal(envelope)
    if err != nil { return err }
    if _, err := voin.VerifyTransfer(raw); err != nil { return err }
    return json.NewEncoder(os.Stdout).Encode(struct {
        Sender string `json:"sender"`
        Recipient string `json:"recipient"`
        Genesis [][]string `json:"genesis"`
        Transaction json.RawMessage `json:"transaction"`
    }{sender, recipient, [][]string{{sender, "1000"}}, raw})
}
'''


def command(args, cwd, timeout=240):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("Command failed: " + " ".join(map(str, args)) + "\n" +
                           (result.stdout + result.stderr)[-5000:])
    return result.stdout


def rpc(method, **params):
    url = "http://127.0.0.1:28657/" + method + "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=4) as response:
            data = json.load(response)
    except urllib.error.HTTPError as error:
        body = error.read().decode(errors="replace")
        raise RuntimeError(f"RPC HTTP {error.code}: {body[:1000]}") from error
    if "error" in data:
        raise RuntimeError(str(data["error"]))
    return data["result"]


def wait_for(action, processes, timeout=60):
    deadline = time.monotonic() + timeout
    last = "not ready"
    while time.monotonic() < deadline:
        if any(process.poll() is not None for process in processes):
            raise RuntimeError("A lab process exited; see app.log/node.log")
        try:
            result = action()
            if result:
                return result
        except Exception as error:
            last = str(error)
        time.sleep(0.5)
    raise RuntimeError("Wait timed out: " + last)


def patch_config(path):
    changes = {
        ("", "proxy_app"): '"tcp://127.0.0.1:28658"',
        ("", "abci"): '"socket"',
        ("", "pprof_laddr"): '""',
        ("[rpc]", "laddr"): '"tcp://127.0.0.1:28657"',
        ("[rpc]", "grpc_laddr"): '""',
        ("[rpc]", "unsafe"): 'false',
        ("[p2p]", "laddr"): '"tcp://127.0.0.1:28656"',
        ("[p2p]", "persistent_peers"): '""',
        ("[p2p]", "seeds"): '""',
        ("[grpc]", "laddr"): '""',
        ("[grpc.privileged]", "laddr"): '""',
        ("[instrumentation]", "prometheus"): 'false',
    }
    section = ""
    lines = []
    for line in path.read_text().splitlines():
        if line.startswith("["):
            section = line.strip()
        for (group, key), value in changes.items():
            if section == group and re.match(r"^" + re.escape(key) + r"\s*=", line):
                line = key + " = " + value
        lines.append(line)
    updated = "\n".join(lines) + "\n"
    import tomllib
    config = tomllib.loads(updated)
    assert config["proxy_app"] == "tcp://127.0.0.1:28658"
    assert config["rpc"]["laddr"] == "tcp://127.0.0.1:28657"
    assert config["p2p"]["laddr"] == "tcp://127.0.0.1:28656"
    path.write_text(updated)


def main():
    os.umask(0o077)
    repo = Path(command(["git", "rev-parse", "--show-toplevel"], Path.cwd()).strip())
    module = repo / "consensus/voin-app"
    branch = command(["git", "branch", "--show-current"], repo).strip()
    if branch != "feature/signed-transfers":
        raise RuntimeError("Use branch feature/signed-transfers; no branch was changed")
    comet = Path.home() / "voin-tools/bin/cometbft"
    if not comet.is_file():
        raise RuntimeError("CometBFT binary not found")
    if "1.0.1" not in command([str(comet), "version"], repo):
        raise RuntimeError("This experiment requires CometBFT 1.0.1")
    for port in (28656, 28657, 28658):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
    lab = Path(tempfile.mkdtemp(prefix="voin-transfer-lab-", dir=Path.home()))
    print("LAB:", lab, flush=True)
    print("No real assets. Do not forward ports. Private keys are not exported.", flush=True)
    processes = []
    log_handles = []
    try:
        source_dir = module / "cmd/voin-transfer-lab"
        source_dir.mkdir(parents=True, exist_ok=True)
        source = source_dir / "main.go"
        if source.exists():
            # Compare formatted source without overwriting existing edits.
            existing = subprocess.run(["gofmt"], input=source.read_text(),
                                      capture_output=True, text=True, timeout=30, check=True).stdout
            proposed = subprocess.run(["gofmt"], input=GO_SOURCE,
                                      capture_output=True, text=True, timeout=30, check=True).stdout
            if existing != proposed:
                raise RuntimeError("Existing cmd/voin-transfer-lab/main.go differs; not overwritten")
        else:
            with source.open("x") as stream:
                stream.write(GO_SOURCE)
        command(["gofmt", "-w", str(source)], module, timeout=30)
        print("RUN: Go race tests and vet", flush=True)
        command(["go", "test", "-race", "./...", "-count=1", "-timeout=120s"], module)
        command(["go", "vet", "./..."], module)
        print("PASS: Go checks", flush=True)
        binary = lab / "voin-transfer-lab"
        command(["go", "build", "-o", str(binary), "./cmd/voin-transfer-lab"], module)
        fixture = json.loads(command([str(binary), "-fixture"], repo, timeout=30))
        raw = json.dumps(fixture["transaction"], separators=(",", ":")).encode()
        # JSON field order from Go is preserved by Python; canonical input is checked by the app.
        (lab / "fixture-public.json").write_text(json.dumps(fixture, indent=2))
        node_home = lab / "node"
        command([str(comet), "init", "--home", str(node_home)], repo, timeout=30)
        genesis_path = node_home / "config/genesis.json"
        genesis = json.loads(genesis_path.read_text())
        genesis.update(chain_id="voin-devnet-1", initial_height="1", app_hash="",
                       app_state=fixture["genesis"])
        genesis_path.write_text(json.dumps(genesis, indent=2))
        patch_config(node_home / "config/config.toml")
        for name, args in (
            ("app", [str(binary), "-state", str(lab / "state.json")]),
            ("node", [str(comet), "node", "--home", str(node_home)]),
        ):
            log = (lab / (name + ".log")).open("ab")
            log_handles.append(log)
            process = subprocess.Popen(args, cwd=repo, stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=log, start_new_session=True)
            processes.append(process)
            if name == "app":
                time.sleep(1)
                if process.poll() is not None:
                    raise RuntimeError("Transfer server exited; see app.log")
        wait_for(lambda: int(rpc("status")["sync_info"]["latest_block_height"]) >= 1,
                 processes)
        print("PASS: fresh transfer node produces blocks", flush=True)
        submitted = rpc("broadcast_tx_sync", tx="0x" + raw.hex())
        if int(submitted.get("code", 0)) != 0:
            raise RuntimeError("CheckTx rejected test transfer: " + str(submitted))
        tx_hash = hashlib.sha256(raw).hexdigest().upper()
        confirmed = wait_for(lambda: rpc("tx", hash="0x" + tx_hash, prove="false"), processes)
        if int(confirmed["tx_result"].get("code", 0)) != 0:
            raise RuntimeError("Transaction execution failed")
        tx_height = int(confirmed["height"])
        block = rpc("block", height=tx_height)["block"]
        transactions = block.get("data", {}).get("txs") or []
        if raw not in [base64.b64decode(value) for value in transactions]:
            raise RuntimeError("Signed transaction absent from reported block")
        def balances():
            state = json.loads((lab / "state.json").read_bytes())
            accounts = state["accounts"]
            sender = accounts[fixture["sender"]]
            receiver = accounts[fixture["recipient"]]
            return state if (sender["balance"] == 750 and sender["nonce"] == 1
                             and receiver["balance"] == 250) else None
        state = wait_for(balances, processes)
        captured = (lab / "state.json").read_bytes()
        captured_state = json.loads(captured)
        next_height = captured_state["height"] + 1
        wait_for(lambda: int(rpc("status")["sync_info"]["latest_block_height"]) >= next_height,
                 processes)
        recorded = rpc("block", height=next_height)["block"]["header"]["app_hash"]
        if recorded.upper() != hashlib.sha256(captured).hexdigest().upper():
            raise RuntimeError("Committed state hash differs from next block header")
        print("PASS: transfer committed in block", tx_height, flush=True)
        print("PASS: Alice=750, Bob=250, Alice nonce=1", flush=True)
        print("PASS: saved state hash matches next block", flush=True)
        report = {
            "result": "PASS", "scope": "single local validator signed transfer",
            "transaction_height": tx_height, "transaction_hash": tx_hash,
            "sender_balance": 750, "recipient_balance": 250, "sender_nonce": 1,
            "not_tested": ["server restart", "multi-validator transfers", "crash recovery",
                           "adversarial network", "performance", "production safety"],
        }
        (lab / "result.json").write_text(json.dumps(report, indent=2))
        print("TRANSFER LAB PASS. This is not a mainnet or exchange.", flush=True)
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    # Only processes started and owned by this invocation are affected.
                    process.kill()
                    process.wait(timeout=10)
                    print("WARNING: forced stop; this lab is not a crash-safety test", flush=True)
        for log in log_handles:
            log.close()
        print("Lab data/logs kept privately at:", lab, flush=True)
        print("Old labs unchanged. No git commit or push performed.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Stopped by user; inspect lab logs before retrying.")
        raise SystemExit(130)
    except Exception as error:
        print("TRANSFER LAB NOT PASSED:", error, flush=True)
        raise SystemExit(1)
