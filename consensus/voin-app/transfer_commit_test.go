package voinapp

import (
	"context"
	abci "github.com/cometbft/cometbft/abci/types"
	"testing"
)

func TestTransferFinalizeThenCommit(t *testing.T) {
	state, envelope, sk := testTransferFixture(t)
	app, err := NewTransferApp(&App{state: state})
	if err != nil {
		t.Fatal(err)
	}
	raw := signTestTransfer(t, envelope, sk)
	before, err := state.Hash()
	if err != nil {
		t.Fatal(err)
	}
	response, err := app.FinalizeBlock(context.Background(),
		&abci.FinalizeBlockRequest{
			Height: state.Height + 1, Txs: [][]byte{raw},
		})
	if err != nil {
		t.Fatal(err)
	}
	active, err := app.state.Hash()
	if err != nil || active != before || app.pending == nil {
		t.Fatal("finalize changed active state or lost pending state")
	}
	if len(response.TxResults) != 1 || response.TxResults[0].Code != 0 {
		t.Fatal("missing successful transaction result")
	}
	if _, err := app.Commit(context.Background(), &abci.CommitRequest{}); err != nil {
		t.Fatal(err)
	}
	if app.pending != nil ||
		app.state.Accounts[envelope.Transfer.Sender].Balance != 750 ||
		app.state.Accounts[envelope.Transfer.Recipient].Balance != 250 {
		t.Fatal("commit did not activate transfer correctly")
	}
}
