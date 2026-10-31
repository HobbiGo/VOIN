package voinapp

import (
	"errors"

	abci "github.com/cometbft/cometbft/abci/types"
)

func (app *App) finalizeEmptyBlock(
	req *abci.FinalizeBlockRequest,
) (*abci.FinalizeBlockResponse, error) {
	if app == nil || req == nil {
		return nil, errors.New("missing application or request")
	}
	if len(req.Txs) != 0 {
		return nil, processingDisabledError{}
	}
	if app.state == nil {
		return nil, errors.New("application not initialized")
	}
	if app.pending != nil {
		return nil, errors.New("previous block awaits commit")
	}
	if err := app.state.Validate(); err != nil {
		return nil, err
	}
	if req.Height <= 0 || req.Height != app.state.Height+1 {
		return nil, errors.New("unexpected block height")
	}

	next := &State{
		ChainID:  app.state.ChainID,
		Height:   req.Height,
		Accounts: make(map[string]Account, len(app.state.Accounts)),
	}
	for address, account := range app.state.Accounts {
		next.Accounts[address] = account
	}
	hash, err := next.Hash()
	if err != nil {
		return nil, err
	}

	app.pending = next
	return &abci.FinalizeBlockResponse{AppHash: hash[:]}, nil
}
