package voinapp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
)

func TestFreshAppPersistsFirstBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	app, err := NewFreshPersistentApp(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := app.InitChain(ctx, genesisRequest(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := app.FinalizeBlock(
		ctx, &abci.FinalizeBlockRequest{Height: 1},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Commit(ctx, &abci.CommitRequest{}); err != nil {
		t.Fatal(err)
	}
	trusted, err := app.StateHash()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAppFromCheckpoint(path, trusted); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFreshPersistentApp(path); err == nil {
		t.Fatal("existing state accepted as a new application")
	}
}

func TestFreshAppRejectsUnsafePaths(t *testing.T) {
	folder := t.TempDir()
	existing := filepath.Join(folder, "existing.json")
	if err := os.WriteFile(existing, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"", "relative.json", existing,
		filepath.Join(folder, "missing", "state.json"),
	} {
		if _, err := NewFreshPersistentApp(path); err == nil {
			t.Fatalf("path accepted: %q", path)
		}
	}
	data, err := os.ReadFile(existing)
	if err != nil || string(data) != "keep" {
		t.Fatal("existing file changed")
	}
}
