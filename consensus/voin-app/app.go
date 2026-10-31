package voinapp

import (
	"context"

	abci "github.com/cometbft/cometbft/abci/types"
)

// App is an unfinished scaffold, not a runnable VOIN ledger.
type App struct {
	abci.BaseApplication
}

var _ abci.Application = (*App)(nil)

func NewApp() *App {
	return &App{}
}

func (app *App) CheckTx(
	ctx context.Context,
	req *abci.CheckTxRequest,
) (*abci.CheckTxResponse, error) {
	return &abci.CheckTxResponse{
		Code: 1,
		Log:  "VOIN transaction processing is not enabled",
	}, nil
}

// PrepareProposal excludes all transactions while processing is disabled.
func (app *App) PrepareProposal(
	ctx context.Context,
	req *abci.PrepareProposalRequest,
) (*abci.PrepareProposalResponse, error) {
	return &abci.PrepareProposalResponse{Txs: nil}, nil
}

// CometBFT 1.0.1 proposal status: ACCEPT=1, REJECT=2.
func (app *App) ProcessProposal(
	ctx context.Context,
	req *abci.ProcessProposalRequest,
) (*abci.ProcessProposalResponse, error) {
	status := 1
	if len(req.Txs) != 0 {
		status = 2
	}
	result := &abci.ProcessProposalResponse{}
	if status == 1 {
		result.Status = 1
	} else {
		result.Status = 2
	}
	return result, nil
}

type processingDisabledError struct{}

func (processingDisabledError) Error() string {
	return "VOIN transaction execution is not enabled"
}

func (app *App) FinalizeBlock(
	ctx context.Context,
	req *abci.FinalizeBlockRequest,
) (*abci.FinalizeBlockResponse, error) {
	if len(req.Txs) != 0 {
		return nil, processingDisabledError{}
	}
	return &abci.FinalizeBlockResponse{}, nil
}
