package voinapp

import (
	"bytes"
	"context"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
)

func TestFinalizeStagesWithoutChangingActiveState(t *testing.T) {
	app := NewApp()
	if _, err := app.InitChain(
		context.Background(), genesisRequest(t),
	); err != nil {
		t.Fatal(err)
	}
	before, err := app.StateHash()
	if err != nil {
		t.Fatal(err)
	}
	result, err := app.FinalizeBlock(
		context.Background(),
		&abci.FinalizeBlockRequest{Height: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	if app.state.Height != 0 || app.pending == nil ||
		app.pending.Height != 1 {
		t.Fatal("incorrect active or pending height")
	}
	pendingHash, err := app.pending.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !bytes.Equal(result.AppHash, pendingHash[:]) {
		t.Fatal("response does not match pending state")
	}
	info, err := app.Info(context.Background(), &abci.InfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if info.LastBlockHeight != 0 ||
		!bytes.Equal(info.LastBlockAppHash, before[:]) {
		t.Fatal("Info exposed uncommitted state")
	}
	if _, err := app.FinalizeBlock(
		context.Background(),
		&abci.FinalizeBlockRequest{Height: 2},
	); err == nil {
		t.Fatal("next block accepted before commit")
	}
	app.pending.Accounts["voin_test"] = Account{Balance: 1}
	after, err := app.StateHash()
	if err != nil || after != before {
		t.Fatal("pending state shares active account storage")
	}
}
