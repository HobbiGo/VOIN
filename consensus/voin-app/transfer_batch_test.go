package voinapp

import "testing"

func TestTransferBatchOrderingAndAtomicity(t *testing.T) {
	state, envelope, sk := testTransferFixture(t)
	first := signTestTransfer(t, envelope, sk)
	before, err := state.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeTransferBatch(state, [][]byte{first, first}); err == nil {
		t.Fatal("duplicate nonce accepted in one batch")
	}
	after, err := state.Hash()
	if err != nil || after != before {
		t.Fatal("failed batch changed original state")
	}
	envelope.Transfer.Nonce = 2
	second := signTestTransfer(t, envelope, sk)
	next, err := executeTransferBatch(state, [][]byte{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if next.Accounts[envelope.Transfer.Sender].Balance != 500 ||
		next.Accounts[envelope.Transfer.Sender].Nonce != 2 ||
		next.Accounts[envelope.Transfer.Recipient].Balance != 500 {
		t.Fatal("incorrect sequential batch result")
	}
	after, err = state.Hash()
	if err != nil || after != before {
		t.Fatal("successful batch changed original state")
	}
}
