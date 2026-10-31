package voinapp

import (
	"context"

	abci "github.com/cometbft/cometbft/abci/types"
)

func (app *TransferApp) ProcessProposal(
	ctx context.Context, req *abci.ProcessProposalRequest,
) (*abci.ProcessProposalResponse, error) {
	reject := &abci.ProcessProposalResponse{Status: 2}
	if app == nil || app.App == nil || req == nil {
		return reject, nil
	}
	if app.state == nil || app.pending != nil {
		return reject, nil
	}
	if req.Height <= 0 || req.Height != app.state.Height+1 {
		return reject, nil
	}
	if _, err := executeTransferBatch(app.state, req.Txs); err != nil {
		return reject, nil
	}
	return &abci.ProcessProposalResponse{Status: 1}, nil
}
