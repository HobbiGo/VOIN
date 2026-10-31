package voinapp

import (
	"context"
	"errors"
	abci "github.com/cometbft/cometbft/abci/types"
)

func (app *TransferApp) FinalizeBlock(
	ctx context.Context, req *abci.FinalizeBlockRequest,
) (*abci.FinalizeBlockResponse, error) {
	if app != nil {
		app.mu.Lock()
		defer app.mu.Unlock()
	}
	if app == nil || app.App == nil || req == nil {
		return nil, errors.New("missing app or request")
	}
	if app.state == nil || app.pending != nil {
		return nil, errors.New("uninitialized app or pending commit")
	}
	if req.Height <= 0 || req.Height != app.state.Height+1 {
		return nil, errors.New("unexpected block height")
	}
	next, err := executeTransferBatch(app.state, req.Txs)
	if err != nil {
		return nil, err
	}
	next.Height = req.Height
	hash, err := next.Hash()
	if err != nil {
		return nil, err
	}
	results := make([]*abci.ExecTxResult, len(req.Txs))
	for i := range results {
		results[i] = &abci.ExecTxResult{Code: 0}
	}
	app.pending = next
	return &abci.FinalizeBlockResponse{
		AppHash: hash[:], TxResults: results,
	}, nil
}
