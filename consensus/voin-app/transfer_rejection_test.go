package voinapp

import (
	"context"
	abci "github.com/cometbft/cometbft/abci/types"
	"testing"
)

func TestRejectedTransferBlockPreservesState(t *testing.T) {
	state, envelope, sk := testTransferFixture(t)
	app, err := NewTransferApp(&App{state: state})
	if err != nil {
		t.Fatal(err)
	}
	raw := signTestTransfer(t, envelope, sk)
	txs := [][]byte{raw, raw}
	before, err := state.Hash()
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := app.ProcessProposal(context.Background(),
		&abci.ProcessProposalRequest{
			Height: state.Height + 1, Txs: txs,
		})
	if err != nil || proposal.Status != 2 {
		t.Fatal("duplicate transaction proposal not rejected")
	}
	_, err = app.FinalizeBlock(context.Background(),
		&abci.FinalizeBlockRequest{
			Height: state.Height + 1, Txs: txs,
		})
	if err == nil || app.pending != nil {
		t.Fatal("invalid block accepted or left pending state")
	}
	after, err := app.state.Hash()
	if err != nil || after != before {
		t.Fatal("rejected block changed active state")
	}
}
