package voinapp

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
)

const ChainID = "voin-devnet-1"

var accountPattern = regexp.MustCompile(`^voin_[0-9a-f]{64}$`)

type Account struct {
	Balance uint64 `json:"balance"`
	Nonce   uint64 `json:"nonce"`
}

type State struct {
	ChainID  string             `json:"chain_id"`
	Height   int64              `json:"height"`
	Accounts map[string]Account `json:"accounts"`
}

func NewState(allocations map[string]uint64) (*State, error) {
	if len(allocations) == 0 {
		return nil, errors.New("genesis allocations required")
	}
	accounts := make(map[string]Account, len(allocations))
	for address, balance := range allocations {
		if !accountPattern.MatchString(address) || balance == 0 {
			return nil, errors.New("invalid genesis allocation")
		}
		accounts[address] = Account{Balance: balance}
	}
	return &State{
		ChainID:  ChainID,
		Height:   0,
		Accounts: accounts,
	}, nil
}

func (state *State) Hash() ([32]byte, error) {
	if err := state.Validate(); err != nil {
		return [32]byte{}, err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}

// Validate checks structural invariants, not transaction authorization.
func (state *State) Validate() error {
	if state == nil {
		return errors.New("missing state")
	}
	if state.ChainID != ChainID {
		return errors.New("wrong state network")
	}
	if state.Height < 0 {
		return errors.New("negative state height")
	}
	if len(state.Accounts) == 0 {
		return errors.New("missing accounts")
	}
	for address := range state.Accounts {
		if !accountPattern.MatchString(address) {
			return errors.New("invalid account address")
		}
	}
	return nil
}
