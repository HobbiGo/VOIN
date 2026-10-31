package voinapp

import "errors"

// ApplySignedTransfer returns a new state without mutating the input.
// Block height is managed separately by the ABCI block lifecycle.
func ApplySignedTransfer(state *State, raw []byte) (*State, error) {
	if err := state.Validate(); err != nil {
		return nil, err
	}
	tx, err := VerifyTransfer(raw)
	if err != nil {
		return nil, err
	}
	sender, exists := state.Accounts[tx.Sender]
	if !exists {
		return nil, errors.New("sender account not found")
	}
	max := ^uint64(0)
	if sender.Nonce == max || tx.Nonce != sender.Nonce+1 {
		return nil, errors.New("invalid or exhausted nonce")
	}
	if sender.Balance < tx.Amount {
		return nil, errors.New("insufficient balance")
	}
	recipient := state.Accounts[tx.Recipient]
	if recipient.Balance > max-tx.Amount {
		return nil, errors.New("recipient balance overflow")
	}

	next := &State{
		ChainID:  state.ChainID,
		Height:   state.Height,
		Accounts: make(map[string]Account, len(state.Accounts)+1),
	}
	for address, account := range state.Accounts {
		next.Accounts[address] = account
	}
	sender.Balance -= tx.Amount
	sender.Nonce = tx.Nonce
	recipient.Balance += tx.Amount
	next.Accounts[tx.Sender] = sender
	next.Accounts[tx.Recipient] = recipient
	if err := next.Validate(); err != nil {
		return nil, err
	}
	return next, nil
}
