package voinapp

import (
	"strings"
	"testing"
)

func TestAppStateMatchesGenesis(t *testing.T) {
	address := "voin_" + strings.Repeat("a", 64)
	allocations := map[string]uint64{address: 1000}
	app, err := NewAppWithAllocations(allocations)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := NewState(allocations)
	if err != nil {
		t.Fatal(err)
	}
	got, err := app.StateHash()
	if err != nil {
		t.Fatal(err)
	}
	want, err := expected.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("application state differs from genesis")
	}
	allocations[address] = 9999
	after, err := app.StateHash()
	if err != nil || after != got {
		t.Fatal("input mutation changed application state")
	}
}

func TestUninitializedAppHasNoStateHash(t *testing.T) {
	var absent *App
	for _, app := range []*App{absent, NewApp()} {
		if _, err := app.StateHash(); err == nil {
			t.Fatal("uninitialized application must return an error")
		}
	}
}

func TestAppRejectsInvalidAllocations(t *testing.T) {
	if _, err := NewAppWithAllocations(
		map[string]uint64{"alice": 1000},
	); err == nil {
		t.Fatal("invalid allocations accepted")
	}
}
