package voinapp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

func testTransferFixture(t *testing.T) (
	*State, SignedTransfer, *mldsa44.PrivateKey,
) {
	t.Helper()
	pk, sk, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobPK, _, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := pk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	bobPublic, err := bobPK.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	senderHash := sha256.Sum256(public)
	recipientHash := sha256.Sum256(bobPublic)
	sender := "voin_" + hex.EncodeToString(senderHash[:])
	recipient := "voin_" + hex.EncodeToString(recipientHash[:])
	state, err := NewState(map[string]uint64{sender: 1000})
	if err != nil {
		t.Fatal(err)
	}
	envelope := SignedTransfer{
		Transfer: Transfer{
			Version: 1, ChainID: ChainID,
			Sender: sender, Recipient: recipient,
			Amount: 250, Nonce: 1,
		},
		PublicKey: hex.EncodeToString(public),
	}
	return state, envelope, sk
}

func signTestTransfer(
	t *testing.T, envelope SignedTransfer, sk *mldsa44.PrivateKey,
) []byte {
	t.Helper()
	message, err := json.Marshal(envelope.Transfer)
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, mldsa44.SignatureSize)
	if err := mldsa44.SignTo(
		sk, message, transferContext, false, signature,
	); err != nil {
		t.Fatal(err)
	}
	envelope.Signature = hex.EncodeToString(signature)
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
