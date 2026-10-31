package voinapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

func readStateFile(path string, trustedHash [32]byte) (*State, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, MaxStateFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > MaxStateFileBytes {
		return nil, errors.New("invalid state file size")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state State
	if err := decoder.Decode(&state); err != nil {
		return nil, err
	}
	hash, err := state.Hash()
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(&state)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(data, canonical) {
		return nil, errors.New("state file is not canonical")
	}
	if hash != trustedHash {
		return nil, errors.New("state does not match trusted checkpoint")
	}
	return &state, nil
}
