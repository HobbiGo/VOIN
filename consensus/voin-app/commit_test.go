package voinapp

import (
	"bytes"
	"context"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
)

func TestCommitActivatesPendingState(t *testing.T) {
	ctx := context.Background()
	app := NewApp()
	if _, err := app.InitChain(ctx, genesisRequest(t)); err != nil {
		t.Fatal(err)
	}
	block, err := app.FinalizeBlock(
		ctx, &abci.FinalizeBlockRequest{Height: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Commit(ctx, &abci.CommitRequest{}); err != nil {
		t.Fatal(err)
	}
	info, err := app.Info(ctx, &abci.InfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if info.LastBlockHeight != 1 {
		t.Fatal("incorrect committed height")
	}
	if !bytes.Equal(info.LastBlockAppHash, block.AppHash) {
		t.Fatal("incorrect committed hash")
	}
	if app.pending != nil {
		t.Fatal("pending state was not cleared")
	}
	before, err := app.StateHash()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Commit(ctx, &abci.CommitRequest{}); err == nil {
		t.Fatal("commit without a new block accepted")
	}
	after, err := app.StateHash()
	if err != nil || before != after {
		t.Fatal("rejected commit changed state")
	}
	if _, err := app.FinalizeBlock(
		ctx, &abci.FinalizeBlockRequest{Height: 2},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Commit(ctx, &abci.CommitRequest{}); err != nil {
		t.Fatal(err)
	}
	if app.state.Height != 2 {
		t.Fatal("second block not committed")
	}
}

func TestCommitWithoutInitializationRejected(t *testing.T) {
	app := NewApp()
	if _, err := app.Commit(
		context.Background(), &abci.CommitRequest{},
	); err == nil {
		t.Fatal("uninitialized commit accepted")
	}
}
