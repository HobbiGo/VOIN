// Package walletcrypto provides experimental authenticated encryption for TEST wallets.
package walletcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/scrypt"
	"io"
)

const MaxPlaintext = 20000
const MaxEnvelope = 40000
const kdfName = "scrypt-N131072-r8-p1"
const cipherName = "AES-256-GCM"

var aad = []byte("VOIN/test-wallet-storage/v1|" + kdfName + "|" + cipherName)

type envelope struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Cipher     string `json:"cipher"`
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func Wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
func aead(password, salt []byte) (cipher.AEAD, error) {
	if len(password) < 12 || len(password) > 1024 {
		return nil, errors.New("password must be 12-1024 bytes")
	}
	key, err := scrypt.Key(password, salt, 131072, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	defer Wipe(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func Seal(plain, password []byte) ([]byte, error) {
	if len(plain) == 0 || len(plain) > MaxPlaintext {
		return nil, errors.New("invalid plaintext size")
	}
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	box, err := aead(password, salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, box.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return json.Marshal(envelope{1, kdfName, cipherName, salt, nonce, box.Seal(nil, nonce, plain, aad)})
}
func Open(raw, password []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxEnvelope {
		return nil, errors.New("invalid envelope size")
	}
	var value envelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("invalid envelope")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, errors.New("noncanonical envelope")
	}
	if value.Version != 1 || value.KDF != kdfName || value.Cipher != cipherName ||
		len(value.Salt) != 32 || len(value.Nonce) != 12 || len(value.Ciphertext) < 17 ||
		len(value.Ciphertext) > MaxPlaintext+16 {
		return nil, errors.New("unsupported or invalid envelope")
	}
	box, err := aead(password, value.Salt)
	if err != nil {
		return nil, err
	}
	plain, err := box.Open(nil, value.Nonce, value.Ciphertext, aad)
	if err != nil {
		return nil, errors.New("wrong password or damaged encrypted wallet")
	}
	return plain, nil
}
