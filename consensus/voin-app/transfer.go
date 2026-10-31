package voinapp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

const MaxTransferBytes = 12000

var transferContext = []byte("VOIN/transfer/v1")

type Transfer struct {
	Version   uint8  `json:"version"`
	ChainID   string `json:"chain_id"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Amount    uint64 `json:"amount"`
	Nonce     uint64 `json:"nonce"`
}

type SignedTransfer struct {
	Transfer  Transfer `json:"transfer"`
	PublicKey string   `json:"public_key"`
	Signature string   `json:"signature"`
}

func transferMessage(tx Transfer) ([]byte, error) {
	if tx.Version != 1 || tx.ChainID != ChainID {
		return nil, errors.New("unsupported transfer version or network")
	}
	if !accountPattern.MatchString(tx.Sender) ||
		!accountPattern.MatchString(tx.Recipient) ||
		tx.Sender == tx.Recipient {
		return nil, errors.New("invalid transfer addresses")
	}
	if tx.Amount == 0 || tx.Nonce == 0 {
		return nil, errors.New("amount and nonce must be positive")
	}
	return json.Marshal(tx)
}

func decodeTransferHex(value string, size int) ([]byte, error) {
	if len(value) != size*2 {
		return nil, errors.New("invalid cryptographic input length")
	}
	data, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(data) != value {
		return nil, errors.New("invalid canonical hex")
	}
	return data, nil
}

func VerifyTransfer(raw []byte) (Transfer, error) {
	var envelope SignedTransfer
	fail := func(err error) (Transfer, error) {
		return Transfer{}, err
	}
	if len(raw) == 0 || len(raw) > MaxTransferBytes {
		return fail(errors.New("invalid transaction size"))
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return fail(err)
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(raw, canonical) {
		return fail(errors.New("transaction is not canonical JSON"))
	}
	message, err := transferMessage(envelope.Transfer)
	if err != nil {
		return fail(err)
	}
	public, err := decodeTransferHex(envelope.PublicKey, mldsa44.PublicKeySize)
	if err != nil {
		return fail(err)
	}
	signature, err := decodeTransferHex(envelope.Signature, mldsa44.SignatureSize)
	if err != nil {
		return fail(err)
	}
	addressHash := sha256.Sum256(public)
	if envelope.Transfer.Sender != "voin_"+hex.EncodeToString(addressHash[:]) {
		return fail(errors.New("sender does not match public key"))
	}
	var key mldsa44.PublicKey
	if err := key.UnmarshalBinary(public); err != nil {
		return fail(err)
	}
	if !mldsa44.Verify(&key, message, transferContext, signature) {
		return fail(errors.New("invalid transaction signature"))
	}
	return envelope.Transfer, nil
}
