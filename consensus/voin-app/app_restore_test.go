package voinapp

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
)

func TestRestoredAppContinuesFromCheckpoint(t *testing.T) {
	ctx := context.Background()
	original := pendingApp(t)
	path := filepath.Join(t.TempDir(), "state.json")
	original.stateFile = path
	if _, err := original.Commit(ctx, &abci.CommitRequest{}); err != nil {
		t.Fatal(err)
	}
	trusted, err := original.StateHash()
	if err != nil {
		t.Fatal(err)
	}

	restored, err := NewAppFromCheckpoint(path, trusted)
	if err != nil {
		t.Fatal(err)
	}
	info, err := restored.Info(ctx, &abci.InfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if info.LastBlockHeight != 1 ||
		!bytes.Equal(info.LastBlockAppHash, trusted[:]) {
		t.Fatal("restored application reported incorrect checkpoint")
	}
	if _, err := restored.InitChain(ctx, genesisRequest(t)); err == nil {
		t.Fatal("restored application allowed reinitialization")
	}
	block, err := restored.FinalizeBlock(
		ctx, &abci.FinalizeBlockRequest{Height: 2},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restored.Commit(ctx, &abci.CommitRequest{}); err != nil {
		t.Fatal(err)
	}
	latest, err := restored.StateHash()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(latest[:], block.AppHash) {
		t.Fatal("committed hash differs from finalized block")
	}
	again, err := NewAppFromCheckpoint(path, latest)
	if err != nil {
		t.Fatal(err)
	}
	if again.state.Height != 2 {
		t.Fatal("continued state was not persisted")
	}
}
