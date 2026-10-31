package voinapp

import (
	"context"
	"errors"

	abci "github.com/cometbft/cometbft/abci/types"
)

func (app *App) Commit(
	ctx context.Context,
	req *abci.CommitRequest,
) (*abci.CommitResponse, error) {
	if app == nil || req == nil {
		return nil, errors.New("missing application or request")
	}
	if app.state == nil || app.pending == nil {
		return nil, errors.New("no pending block to commit")
	}
	if err := app.state.Validate(); err != nil {
		return nil, err
	}
	if app.pending.Height <= 0 ||
		app.pending.Height != app.state.Height+1 {
		return nil, errors.New("unexpected pending height")
	}
	if _, err := app.pending.Hash(); err != nil {
		return nil, err
	}

	app.state = app.pending
	app.pending = nil
	return &abci.CommitResponse{}, nil
}
