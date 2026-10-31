package voinapp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
)

func genesisRequest(t *testing.T) *abci.InitChainRequest {
	t.Helper()
	address := "voin_" + strings.Repeat("a", 64)
	data, err := json.Marshal([][]string{{address, "1000"}})
	if err != nil {
		t.Fatal(err)
	}
	return &abci.InitChainRequest{
		ChainId:       ChainID,
		InitialHeight: 1,
		AppStateBytes: data,
	}
}

func TestInitChainSetsState(t *testing.T) {
	app := NewApp()
	response, err := app.InitChain(context.Background(), genesisRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := app.StateHash()
	if err != nil {
		t.Fatal(err)
	}
	if response == nil || !bytes.Equal(response.AppHash, hash[:]) {
		t.Fatal("genesis response does not match state hash")
	}
	address := "voin_" + strings.Repeat("a", 64)
	if app.state.Accounts[address].Balance != 1000 {
		t.Fatal("incorrect genesis balance")
	}
}

func TestInitChainRejectsSecondInitialization(t *testing.T) {
	app := NewApp()
	request := genesisRequest(t)
	if _, err := app.InitChain(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	before, err := app.StateHash()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.InitChain(context.Background(), request); err == nil {
		t.Fatal("second initialization accepted")
	}
	after, err := app.StateHash()
	if err != nil || before != after {
		t.Fatal("rejected initialization changed state")
	}
}

func TestInvalidInitChainLeavesStateUnset(t *testing.T) {
	cases := map[string]func(*abci.InitChainRequest){
		"wrong network": func(r *abci.InitChainRequest) {
			r.ChainId = "other-network"
		},
		"wrong height": func(r *abci.InitChainRequest) {
			r.InitialHeight = 2
		},
		"empty allocations": func(r *abci.InitChainRequest) {
			r.AppStateBytes = []byte("[]")
		},
		"trailing data": func(r *abci.InitChainRequest) {
			r.AppStateBytes = append(r.AppStateBytes, []byte(" []")...)
		},
		"duplicate address": func(r *abci.InitChainRequest) {
			address := "voin_" + strings.Repeat("a", 64)
			r.AppStateBytes, _ = json.Marshal([][]string{
				{address, "1000"}, {address, "2000"},
			})
		},
		"noncanonical amount": func(r *abci.InitChainRequest) {
			address := "voin_" + strings.Repeat("a", 64)
			r.AppStateBytes, _ = json.Marshal(
				[][]string{{address, "01000"}},
			)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			app := NewApp()
			request := genesisRequest(t)
			change(request)
			if _, err := app.InitChain(context.Background(), request); err == nil {
				t.Fatal("invalid genesis accepted")
			}
			if app.state != nil {
				t.Fatal("failed initialization changed state")
			}
		})
	}
}
