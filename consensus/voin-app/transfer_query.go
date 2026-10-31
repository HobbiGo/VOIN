package voinapp

import (
	"context"
	"encoding/json"
	abci "github.com/cometbft/cometbft/abci/types"
)

// Query exposes a local committed account snapshot, NOT a Merkle proof.
func (app *TransferApp) Query(ctx context.Context, req *abci.QueryRequest) (*abci.QueryResponse, error) {
	if app == nil || app.App == nil || req == nil {
		return &abci.QueryResponse{Code: 1, Log: "missing application or request"}, nil
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.state == nil || req.Path != "/account" || req.Prove ||
		(req.Height != 0 && req.Height != app.state.Height) ||
		len(req.Data) != 69 || !accountPattern.Match(req.Data) {
		return &abci.QueryResponse{Code: 1, Log: "unsupported account query"}, nil
	}
	account, exists := app.state.Accounts[string(req.Data)]
	if !exists {
		return &abci.QueryResponse{Code: 1, Log: "account not found", Height: app.state.Height}, nil
	}
	value, err := json.Marshal(account)
	if err != nil {
		return nil, err
	}
	return &abci.QueryResponse{Code: 0, Height: app.state.Height,
		Key: append([]byte(nil), req.Data...), Value: value}, nil
}
