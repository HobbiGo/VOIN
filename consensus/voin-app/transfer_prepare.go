package voinapp

import (
	"context"
	abci "github.com/cometbft/cometbft/abci/types"
)

func (app *TransferApp) PrepareProposal(
	ctx context.Context, req *abci.PrepareProposalRequest,
) (*abci.PrepareProposalResponse, error) {
	result := &abci.PrepareProposalResponse{}
	if app == nil || app.App == nil || req == nil {
		return result, nil
	}
	if app.state == nil || app.pending != nil ||
		req.Height <= 0 || req.Height != app.state.Height+1 {
		return result, nil
	}
	budget := req.MaxTxBytes
	if budget > MaxBlockTransferBytes {
		budget = MaxBlockTransferBytes
	}
	next, err := executeTransferBatch(app.state, nil)
	if err != nil || budget <= 0 {
		return result, nil
	}
	for i, raw := range req.Txs {
		if i >= MaxBlockTransfers {
			break
		}
		if len(raw) == 0 || len(raw) > MaxTransferBytes ||
			int64(len(raw)) > budget {
			continue
		}
		updated, err := ApplySignedTransfer(next, raw)
		if err != nil {
			continue
		}
		result.Txs = append(result.Txs, append([]byte(nil), raw...))
		budget -= int64(len(raw))
		next = updated
	}
	return result, nil
}
