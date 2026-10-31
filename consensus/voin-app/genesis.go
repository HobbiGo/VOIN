package voinapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
)

const MaxGenesisBytes = 1024 * 1024
const MaxGenesisAccounts = 10000

// Genesis format: [["voin_<64 hex characters>", "1000"], ...]
func ParseGenesis(data []byte) (map[string]uint64, error) {
	if len(data) == 0 || len(data) > MaxGenesisBytes {
		return nil, errors.New("invalid genesis size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var entries [][]string
	if err := decoder.Decode(&entries); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing genesis data")
	}
	if len(entries) == 0 || len(entries) > MaxGenesisAccounts {
		return nil, errors.New("invalid genesis account count")
	}
	allocations := make(map[string]uint64, len(entries))
	for _, entry := range entries {
		if len(entry) != 2 || !accountPattern.MatchString(entry[0]) {
			return nil, errors.New("invalid genesis entry")
		}
		if _, exists := allocations[entry[0]]; exists {
			return nil, errors.New("duplicate genesis address")
		}
		amount, err := strconv.ParseUint(entry[1], 10, 64)
		if err != nil || amount == 0 ||
			strconv.FormatUint(amount, 10) != entry[1] {
			return nil, errors.New("invalid genesis amount")
		}
		allocations[entry[0]] = amount
	}
	return allocations, nil
}
