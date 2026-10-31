package voinapp

import (
	"strings"
	"testing"
)

func TestStateHashIndependentOfInputOrder(t *testing.T) {
	a := "voin_" + strings.Repeat("a", 64)
	b := "voin_" + strings.Repeat("b", 64)

	first, err := NewState(map[string]uint64{a: 1000, b: 500})
	if err != nil {
		t.Fatal(err)
	}
	allocations := make(map[string]uint64)
	allocations[b] = 500
	allocations[a] = 1000
	second, err := NewState(allocations)
	if err != nil {
		t.Fatal(err)
	}
	h1, err := first.Hash()
	if err != nil {
		t.Fatal(err)
	}
	h2, err := second.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatal("same allocations must produce the same hash")
	}
}

func TestStateCopiesAllocations(t *testing.T) {
	a := "voin_" + strings.Repeat("a", 64)
	allocations := map[string]uint64{a: 1000}
	state, err := NewState(allocations)
	if err != nil {
		t.Fatal(err)
	}
	allocations[a] = 9999
	if state.Accounts[a].Balance != 1000 {
		t.Fatal("input mutation changed state")
	}
}

func TestInvalidGenesisRejected(t *testing.T) {
	a := "voin_" + strings.Repeat("a", 64)
	for _, allocations := range []map[string]uint64{
		nil, {}, {"alice": 1000}, {a: 0},
	} {
		if _, err := NewState(allocations); err == nil {
			t.Fatal("invalid genesis accepted")
		}
	}
}

func TestInvalidStateCannotBeHashed(t *testing.T) {
	a := "voin_" + strings.Repeat("a", 64)
	cases := map[string]*State{
		"nil": nil,
		"wrong network": {
			ChainID:  "other-network",
			Accounts: map[string]Account{a: {Balance: 1000}},
		},
		"negative height": {
			ChainID:  ChainID,
			Height:   -1,
			Accounts: map[string]Account{a: {Balance: 1000}},
		},
		"missing accounts": {
			ChainID: ChainID,
		},
		"invalid address": {
			ChainID:  ChainID,
			Accounts: map[string]Account{"alice": {Balance: 1000}},
		},
	}
	for name, state := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := state.Hash(); err == nil {
				t.Fatal("invalid state must not be hashed")
			}
		})
	}
}

func TestZeroBalanceAllowedAfterGenesis(t *testing.T) {
	a := "voin_" + strings.Repeat("a", 64)
	state := &State{
		ChainID:  ChainID,
		Height:   1,
		Accounts: map[string]Account{a: {Balance: 0, Nonce: 1}},
	}
	if _, err := state.Hash(); err != nil {
		t.Fatal(err)
	}
}
