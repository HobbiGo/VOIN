package main

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
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	abciserver "github.com/cometbft/cometbft/abci/server"
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
	if *fixture {
		return makeFixture()
	}
	base, err := voin.NewFreshPersistentApp(*state)
	if err != nil {
		return err
	}
	app, err := voin.NewTransferApp(base)
	if err != nil {
		return err
	}
	server, err := abciserver.NewServer("tcp://127.0.0.1:28658", "socket", app)
	if err != nil {
		return err
	}
	if err := server.Start(); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	<-ctx.Done()
	return server.Stop()
}

func makeFixture() error {
	pk, sk, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	bob, _, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	public, err := pk.MarshalBinary()
	if err != nil {
		return err
	}
	recipientPublic, err := bob.MarshalBinary()
	if err != nil {
		return err
	}
	a := sha256.Sum256(public)
	b := sha256.Sum256(recipientPublic)
	sender := "voin_" + hex.EncodeToString(a[:])
	recipient := "voin_" + hex.EncodeToString(b[:])
	tx := voin.Transfer{Version: 1, ChainID: voin.ChainID,
		Sender: sender, Recipient: recipient, Amount: 250, Nonce: 1}
	message, err := json.Marshal(tx)
	if err != nil {
		return err
	}
	sig := make([]byte, mldsa44.SignatureSize)
	if err := mldsa44.SignTo(sk, message, []byte("VOIN/transfer/v1"), false, sig); err != nil {
		return err
	}
	envelope := voin.SignedTransfer{Transfer: tx,
		PublicKey: hex.EncodeToString(public), Signature: hex.EncodeToString(sig)}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	if _, err := voin.VerifyTransfer(raw); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Sender      string          `json:"sender"`
		Recipient   string          `json:"recipient"`
		Genesis     [][]string      `json:"genesis"`
		Transaction json.RawMessage `json:"transaction"`
	}{sender, recipient, [][]string{{sender, "1000"}}, raw})
}
