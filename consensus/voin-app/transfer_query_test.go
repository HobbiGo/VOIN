package voinapp

import (
	"context"
	"encoding/json"
	abci "github.com/cometbft/cometbft/abci/types"
	"testing"
)

func TestTransferAccountQuery(t *testing.T) {
	state, envelope, _ := testTransferFixture(t)
	app, err := NewTransferApp(&App{state: state})
	if err != nil {
		t.Fatal(err)
	}
	req := &abci.QueryRequest{Path: "/account", Data: []byte(envelope.Transfer.Sender)}
	result, err := app.Query(context.Background(), req)
	if err != nil || result.Code != 0 {
		t.Fatal("account query failed")
	}
	var account Account
	if err := json.Unmarshal(result.Value, &account); err != nil {
		t.Fatal(err)
	}
	if account.Balance != 1000 || account.Nonce != 0 {
		t.Fatal("wrong account")
	}
	req.Prove = true
	result, err = app.Query(context.Background(), req)
	if err != nil || result.Code == 0 {
		t.Fatal("unavailable proof was not rejected")
	}
	req.Prove = false
	req.Data = []byte(envelope.Transfer.Recipient)
	result, err = app.Query(context.Background(), req)
	if err != nil || result.Code == 0 {
		t.Fatal("missing account was not rejected")
	}
}
