package voinapp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
)

func pendingApp(t *testing.T) *App {
	t.Helper()
	app := NewApp()
	ctx := context.Background()
	if _, err := app.InitChain(ctx, genesisRequest(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := app.FinalizeBlock(
		ctx, &abci.FinalizeBlockRequest{Height: 1},
	); err != nil {
		t.Fatal(err)
	}
	return app
}

func TestCommitWritesStateBeforeActivation(t *testing.T) {
	app := pendingApp(t)
	app.stateFile = filepath.Join(t.TempDir(), "state.json")
	expected, err := json.Marshal(app.pending)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Commit(
		context.Background(), &abci.CommitRequest{},
	); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(app.stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, expected) ||
		app.state.Height != 1 || app.pending != nil {
		t.Fatal("stored and active state do not match")
	}
}

func TestFailedWritePreservesActiveAndPendingState(t *testing.T) {
	app := pendingApp(t)
	before, err := app.StateHash()
	if err != nil {
		t.Fatal(err)
	}
	pendingHash, err := app.pending.Hash()
	if err != nil {
		t.Fatal(err)
	}

	folder := t.TempDir()
	app.stateFile = filepath.Join(folder, "missing", "state.json")
	if _, err := app.Commit(
		context.Background(), &abci.CommitRequest{},
	); err == nil {
		t.Fatal("write into missing directory succeeded")
	}
	after, err := app.StateHash()
	if err != nil || after != before || app.pending == nil {
		t.Fatal("failed write changed active or pending state")
	}
	afterPending, err := app.pending.Hash()
	if err != nil || afterPending != pendingHash {
		t.Fatal("failed write changed pending data")
	}

	app.stateFile = filepath.Join(folder, "state.json")
	if _, err := app.Commit(
		context.Background(), &abci.CommitRequest{},
	); err != nil {
		t.Fatal(err)
	}
	if app.state.Height != 1 || app.pending != nil {
		t.Fatal("retry did not commit pending block")
	}
}
