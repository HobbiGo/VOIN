package walletcrypto

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestEncryptedWalletRoundTripAndBackup(t *testing.T) {
	password := []byte("test-only-random-looking-passphrase")
	plain := []byte("TEST PRIVATE PAYLOAD - NOT A REAL KEY")
	first, err := Seal(plain, password)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Seal(plain, password)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) || bytes.Contains(first, plain) {
		t.Fatal("randomization or secrecy failed")
	}
	restored, err := Open(append([]byte(nil), first...), password)
	if err != nil || !bytes.Equal(restored, plain) {
		t.Fatal("backup round trip failed")
	}
	if _, err := Open(first, []byte("different-test-only-passphrase")); err == nil {
		t.Fatal("wrong password accepted")
	}
	var value envelope
	if err := json.Unmarshal(first, &value); err != nil {
		t.Fatal(err)
	}
	value.Ciphertext[0] ^= 1
	changed, _ := json.Marshal(value)
	if _, err := Open(changed, password); err == nil {
		t.Fatal("tampering accepted")
	}
	value.KDF = "scrypt-unbounded-parameters"
	changed, _ = json.Marshal(value)
	if _, err := Open(changed, password); err == nil {
		t.Fatal("unsupported KDF accepted")
	}
	if _, err := Open(append(first, byte(' ')), password); err == nil {
		t.Fatal("extra data accepted")
	}
	if _, err := Seal(plain, []byte("short")); err == nil {
		t.Fatal("short password accepted")
	}
	if _, err := Open(make([]byte, MaxEnvelope+1), password); err == nil {
		t.Fatal("oversized input accepted")
	}
}
