package voinapp

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

const MaxStateFileBytes = 10 * 1024 * 1024

// writeStateFile is a local prototype, not a production database.
func writeStateFile(path string, state *State) error {
	if err := state.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(data) > MaxStateFileBytes {
		return errors.New("state file too large")
	}

	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".voin-state-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}

	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
