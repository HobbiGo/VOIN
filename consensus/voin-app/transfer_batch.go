package voinapp

import "errors"

const MaxBlockTransfers = 100
const MaxBlockTransferBytes = 1024 * 1024

func executeTransferBatch(state *State, txs [][]byte) (*State, error) {
	if state == nil {
		return nil, errors.New("application not initialized")
	}
	if err := state.Validate(); err != nil {
		return nil, err
	}
	if len(txs) > MaxBlockTransfers {
		return nil, errors.New("too many transactions")
	}
	total := 0
	for _, raw := range txs {
		if len(raw) == 0 || len(raw) > MaxTransferBytes {
			return nil, errors.New("invalid transaction size")
		}
		total += len(raw)
		if total > MaxBlockTransferBytes {
			return nil, errors.New("block byte limit exceeded")
		}
	}
	next := &State{
		ChainID: state.ChainID, Height: state.Height,
		Accounts: make(map[string]Account, len(state.Accounts)),
	}
	for address, account := range state.Accounts {
		next.Accounts[address] = account
	}
	for _, raw := range txs {
		updated, err := ApplySignedTransfer(next, raw)
		if err != nil {
			return nil, err
		}
		next = updated
	}
	return next, nil
}
