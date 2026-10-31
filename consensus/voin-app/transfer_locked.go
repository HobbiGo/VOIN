package voinapp

import (
	"context"
	"errors"
	abci "github.com/cometbft/cometbft/abci/types"
)

func (app *TransferApp) InitChain(
	ctx context.Context, req *abci.InitChainRequest,
) (*abci.InitChainResponse, error) {
	if app == nil || app.App == nil {
		return nil, errors.New("missing application")
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	return app.App.InitChain(ctx, req)
}

func (app *TransferApp) Info(
	ctx context.Context, req *abci.InfoRequest,
) (*abci.InfoResponse, error) {
	if app == nil || app.App == nil {
		return nil, errors.New("missing application")
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	return app.App.Info(ctx, req)
}

func (app *TransferApp) Commit(
	ctx context.Context, req *abci.CommitRequest,
) (*abci.CommitResponse, error) {
	if app == nil || app.App == nil {
		return nil, errors.New("missing application")
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	return app.App.Commit(ctx, req)
}
