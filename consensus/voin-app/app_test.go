package voinapp

import (
	"context"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
)

func TestScaffoldRejectsTransactions(t *testing.T) {
	app := NewApp()
	for _, tx := range [][]byte{nil, []byte("alice=bob")} {
		result, err := app.CheckTx(
			context.Background(),
			&abci.CheckTxRequest{Tx: tx},
		)
		if err != nil {
			t.Fatal(err)
		}
		if result == nil || result.Code == 0 {
			t.Fatal("unfinished application must reject transactions")
		}
	}
}

func TestScaffoldRejectsNonemptyProposal(t *testing.T) {
	app := NewApp()
	result, err := app.ProcessProposal(
		context.Background(),
		&abci.ProcessProposalRequest{Txs: [][]byte{[]byte("test")}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Status != 2 {
		t.Fatal("proposal containing transactions must be rejected")
	}
}

func TestScaffoldBlocksDirectExecution(t *testing.T) {
	app := NewApp()
	result, err := app.FinalizeBlock(
		context.Background(),
		&abci.FinalizeBlockRequest{Txs: [][]byte{[]byte("test")}},
	)
	if err == nil || result != nil {
		t.Fatal("unfinished execution must fail closed")
	}
}
