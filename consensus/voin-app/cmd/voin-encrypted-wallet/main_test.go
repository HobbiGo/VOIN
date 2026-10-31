package main

import (
	"bytes"
	voin "example.com/voin/abci"
	"strings"
	"testing"
)

func TestExplicitSigningConfirmation(t *testing.T) {
	tx := voin.Transfer{Version: 1, ChainID: voin.ChainID,
		Sender:    "voin_" + strings.Repeat("a", 64),
		Recipient: "voin_" + strings.Repeat("b", 64), Amount: 1, Nonce: 1}
	for _, value := range []string{"", "\n", "yes\n", "kirim\n", "KIRIM " + "\n"} {
		if err := confirmTransfer(strings.NewReader(value), &bytes.Buffer{}, tx); err == nil {
			t.Fatal("non-exact confirmation accepted")
		}
	}
	var out bytes.Buffer
	if err := confirmTransfer(strings.NewReader("KIRIM\n"), &out, tx); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{tx.ChainID, tx.Sender, tx.Recipient, "Amount: 1", "Nonce: 1"} {
		if !strings.Contains(out.String(), expected) {
			t.Fatal("confirmation omits transfer details")
		}
	}
}
