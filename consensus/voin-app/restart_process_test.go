package voinapp

import (
	"context"
	"encoding/hex"
	"os"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
)

func TestRestoreChildProcess(t *testing.T) {
	if os.Getenv("VOIN_RESTORE_TEST_CHILD") != "1" {
		t.Skip("runs only as a subprocess")
	}
	raw, err := hex.DecodeString(os.Getenv("VOIN_TEST_HASH"))
	if err != nil || len(raw) != 32 {
		t.Fatal("invalid test checkpoint")
	}
	var trusted [32]byte
	copy(trusted[:], raw)
	app, err := NewAppFromCheckpoint(
		os.Getenv("VOIN_TEST_STATE_FILE"), trusted,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	info, err := app.Info(ctx, &abci.InfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if info.LastBlockHeight != 1 {
		t.Fatal("incorrect restored height")
	}
	if _, err := app.FinalizeBlock(
		ctx, &abci.FinalizeBlockRequest{Height: 2},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Commit(ctx, &abci.CommitRequest{}); err != nil {
		t.Fatal(err)
	}
}
