package voinapp

import (
	"context"
	"errors"

	abci "github.com/cometbft/cometbft/abci/types"
)

func (app *App) Info(
	ctx context.Context,
	req *abci.InfoRequest,
) (*abci.InfoResponse, error) {
	if app == nil {
		return nil, errors.New("missing application")
	}
	response := &abci.InfoResponse{
		Data:    "VOIN experimental ABCI application",
		Version: "0.1.0",
	}
	if app.state == nil {
		return response, nil
	}
	hash, err := app.state.Hash()
	if err != nil {
		return nil, err
	}
	response.LastBlockHeight = app.state.Height
	response.LastBlockAppHash = hash[:]
	return response, nil
}
