package voinapp

import (
	"context"
	abci "github.com/cometbft/cometbft/abci/types"
	"path/filepath"
	"testing"
)

func TestCommittedTransferRestores(t *testing.T) {
	state, envelope, sk := testTransferFixture(t)
	path := filepath.Join(t.TempDir(), "state.json")
	app, err := NewTransferApp(&App{state: state, stateFile: path})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	raw := signTestTransfer(t, envelope, sk)
	_, err = app.FinalizeBlock(ctx, &abci.FinalizeBlockRequest{
		Height: state.Height + 1, Txs: [][]byte{raw},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Commit(ctx, &abci.CommitRequest{}); err != nil {
		t.Fatal(err)
	}
	trusted, err := app.state.Hash()
	if err != nil {
		t.Fatal(err)
	}
	base, err := NewAppFromCheckpoint(path, trusted)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := NewTransferApp(base)
	if err != nil {
		t.Fatal(err)
	}
	if restored.state.Accounts[envelope.Transfer.Sender].Balance != 750 ||
		restored.state.Accounts[envelope.Transfer.Sender].Nonce != 1 ||
		restored.state.Accounts[envelope.Transfer.Recipient].Balance != 250 {
		t.Fatal("restored balances or nonce incorrect")
	}
	result, err := restored.CheckTx(ctx, &abci.CheckTxRequest{Tx: raw})
	if err != nil || result.Code == 0 {
		t.Fatal("restored application accepted replay")
	}
}
