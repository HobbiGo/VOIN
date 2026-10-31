package voinapp

import (
	"encoding/json"
	"testing"
)

func TestTamperedTransfersRejected(t *testing.T) {
	state, envelope, sk := testTransferFixture(t)
	raw := signTestTransfer(t, envelope, sk)
	var signed SignedTransfer
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	before, err := state.Hash()
	if err != nil {
		t.Fatal(err)
	}
	signed.Transfer.Amount++
	changed, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := append([]byte(`{"public_key":"00",`), raw[1:]...)
	invalid := [][]byte{
		changed, nil, []byte("{}"), duplicate,
		append(append([]byte{}, raw...), []byte(" {}")...),
		make([]byte, MaxTransferBytes+1),
	}
	for i, data := range invalid {
		if _, err := ApplySignedTransfer(state, data); err == nil {
			t.Fatalf("invalid input %d accepted", i)
		}
		after, err := state.Hash()
		if err != nil || after != before {
			t.Fatalf("input %d changed original state", i)
		}
	}
}
