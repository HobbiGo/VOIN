package voinapp

import (
	"context"
	"errors"

	abci "github.com/cometbft/cometbft/abci/types"
)

func (app *App) InitChain(
	ctx context.Context,
	req *abci.InitChainRequest,
) (*abci.InitChainResponse, error) {
	if app == nil || req == nil {
		return nil, errors.New("missing application or request")
	}
	if app.state != nil {
		return nil, errors.New("application already initialized")
	}
	if req.GetChainId() != ChainID {
		return nil, errors.New("wrong genesis network")
	}
	if req.GetInitialHeight() != 1 {
		return nil, errors.New("only initial height 1 is supported")
	}
	allocations, err := ParseGenesis(req.GetAppStateBytes())
	if err != nil {
		return nil, err
	}
	state, err := NewState(allocations)
	if err != nil {
		return nil, err
	}
	hash, err := state.Hash()
	if err != nil {
		return nil, err
	}
	app.state = state
	return &abci.InitChainResponse{
		AppHash: hash[:],
	}, nil
}
