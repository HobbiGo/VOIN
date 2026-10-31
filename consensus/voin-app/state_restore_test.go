package voinapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestoreMatchesTrustedCheckpoint(t *testing.T) {
	address := "voin_" + strings.Repeat("a", 64)
	state, err := NewState(map[string]uint64{address: 1000})
	if err != nil {
		t.Fatal(err)
	}
	state.Height = 1
	trusted, err := state.Hash()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := writeStateFile(path, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := readStateFile(path, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Height != 1 || loaded.Accounts[address].Balance != 1000 {
		t.Fatal("restored state differs")
	}

	wrong := trusted
	wrong[0] ^= 0xff
	if _, err := readStateFile(path, wrong); err == nil {
		t.Fatal("wrong checkpoint accepted")
	}

	state.Accounts[address] = Account{Balance: 9999}
	if err := writeStateFile(path, state); err != nil {
		t.Fatal(err)
	}
	if _, err := readStateFile(path, trusted); err == nil {
		t.Fatal("modified state accepted against original checkpoint")
	}
}

func TestRestoreRejectsTrailingData(t *testing.T) {
	address := "voin_" + strings.Repeat("a", 64)
	state, err := NewState(map[string]uint64{address: 1000})
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := state.Hash()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := writeStateFile(path, state); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString(" {}")
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("could not prepare test file")
	}
	if _, err := readStateFile(path, trusted); err == nil {
		t.Fatal("trailing data accepted")
	}
}
