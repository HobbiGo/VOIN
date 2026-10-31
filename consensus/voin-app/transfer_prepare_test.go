package voinapp

import (
	"context"
	abci "github.com/cometbft/cometbft/abci/types"
	"testing"
)

func TestPrepareTransferProposal(t *testing.T) {
	state, envelope, sk := testTransferFixture(t)
	app, err := NewTransferApp(&App{state: state})
	if err != nil {
		t.Fatal(err)
	}
	first := signTestTransfer(t, envelope, sk)
	envelope.Transfer.Nonce = 2
	second := signTestTransfer(t, envelope, sk)
	before, err := state.Hash()
	if err != nil {
		t.Fatal(err)
	}
	response, err := app.PrepareProposal(context.Background(),
		&abci.PrepareProposalRequest{
			Height:     state.Height + 1,
			MaxTxBytes: MaxBlockTransferBytes,
			Txs:        [][]byte{[]byte("invalid"), first, first, second},
		})
	if err != nil || len(response.Txs) != 2 {
		t.Fatal("expected two sequential valid transactions")
	}
	checked, err := app.ProcessProposal(context.Background(),
		&abci.ProcessProposalRequest{
			Height: state.Height + 1, Txs: response.Txs,
		})
	if err != nil || checked.Status != 1 {
		t.Fatal("prepared proposal was not accepted")
	}
	after, err := app.state.Hash()
	if err != nil || after != before || app.pending != nil {
		t.Fatal("proposal processing changed application state")
	}
}
