package voinapp

import (
	"bytes"
	"context"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
)

func TestInfoBeforeInitialization(t *testing.T) {
	app := NewApp()
	result, err := app.Info(context.Background(), &abci.InfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.LastBlockHeight != 0 ||
		len(result.LastBlockAppHash) != 0 {
		t.Fatal("uninitialized application reported committed state")
	}
}

func TestInfoAfterInitialization(t *testing.T) {
	app := NewApp()
	genesis, err := app.InitChain(
		context.Background(), genesisRequest(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := app.Info(context.Background(), &abci.InfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.LastBlockHeight != 0 ||
		!bytes.Equal(result.LastBlockAppHash, genesis.AppHash) {
		t.Fatal("Info does not match initialized state")
	}
	result.LastBlockAppHash[0] ^= 0xff
	again, err := app.Info(context.Background(), &abci.InfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.LastBlockAppHash, genesis.AppHash) {
		t.Fatal("changing response modified application hash")
	}
}
