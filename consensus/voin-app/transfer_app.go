package voinapp

import (
	"context"
	"errors"
	"sync"

	abci "github.com/cometbft/cometbft/abci/types"
)

// TransferApp is an explicit experimental transfer mode.
type TransferApp struct {
	mu sync.Mutex
	*App
}

var _ abci.Application = (*TransferApp)(nil)

func NewTransferApp(base *App) (*TransferApp, error) {
	if base == nil || base.pending != nil {
		return nil, errors.New("missing app or uncommitted block")
	}
	return &TransferApp{App: base}, nil
}

func (app *TransferApp) CheckTx(
	ctx context.Context, req *abci.CheckTxRequest,
) (*abci.CheckTxResponse, error) {
	if app != nil {
		app.mu.Lock()
		defer app.mu.Unlock()
	}
	if app == nil || app.App == nil || req == nil {
		return &abci.CheckTxResponse{Code: 1, Log: "missing request or app"}, nil
	}
	if app.state == nil {
		return &abci.CheckTxResponse{Code: 1, Log: "not initialized"}, nil
	}
	if _, err := ApplySignedTransfer(app.state, req.Tx); err != nil {
		return &abci.CheckTxResponse{Code: 1, Log: err.Error()}, nil
	}
	return &abci.CheckTxResponse{Code: 0}, nil
}
