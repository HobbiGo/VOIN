// Experimental Linux TEST-wallet storage tool. Not a spending wallet or 2FA.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	store "example.com/voin/abci/walletcrypto"
	"flag"
	"fmt"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"golang.org/x/term"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

var validName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}$`)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func directory(name string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(home, name)
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("directory must be private and not a symlink")
	}
	return path, nil
}
func pathFor(dir, name string) (string, error) {
	if !validName.MatchString(name) {
		return "", errors.New("invalid filename")
	}
	return filepath.Join(dir, name), nil
}
func readPrivate(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > limit {
		return nil, errors.New("expected a bounded regular0600 file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("file read failed or exceeded limit")
	}
	return data, nil
}
func writeNew(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func password(confirm bool) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("interactive terminal required; no piped passwords")
	}
	fmt.Fprint(os.Stderr, "Test wallet passphrase (12+ bytes, input hidden): ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(first) < 12 || len(first) > 1024 {
		store.Wipe(first)
		return nil, errors.New("passphrase must be12-1024bytes")
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Repeat passphrase (hidden): ")
		second, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		equal := bytes.Equal(first, second)
		store.Wipe(second)
		if err != nil || !equal {
			store.Wipe(first)
			return nil, errors.New("passphrases differ")
		}
	}
	return first, nil
}
func validateKey(plain []byte) (string, error) {
	var value struct {
		Version    int    `json:"version"`
		Address    string `json:"address"`
		PublicKey  string `json:"public_key"`
		PrivateKey string `json:"private_key"`
	}
	if err := json.Unmarshal(plain, &value); err != nil {
		return "", errors.New("invalid test wallet")
	}
	public, err := hex.DecodeString(value.PublicKey)
	if err != nil || len(public) != mldsa44.PublicKeySize || value.Version != 1 {
		return "", errors.New("invalid public key")
	}
	digest := sha256.Sum256(public)
	if value.Address != "voin_"+hex.EncodeToString(digest[:]) {
		return "", errors.New("address mismatch")
	}
	secret, err := hex.DecodeString(value.PrivateKey)
	if err != nil || len(secret) != mldsa44.PrivateKeySize {
		return "", errors.New("invalid private key")
	}
	defer store.Wipe(secret)
	var sk mldsa44.PrivateKey
	var pk mldsa44.PublicKey
	if err := sk.UnmarshalBinary(secret); err != nil {
		return "", errors.New("invalid private key")
	}
	if err := pk.UnmarshalBinary(public); err != nil {
		return "", errors.New("invalid public key")
	}
	signature := make([]byte, mldsa44.SignatureSize)
	message := []byte("VOIN encrypted test wallet key-pair check")
	context := []byte("VOIN/wallet-storage-check/v1")
	if err := mldsa44.SignTo(&sk, message, context, false, signature); err != nil {
		return "", errors.New("key check failed")
	}
	if !mldsa44.Verify(&pk, message, context, signature) {
		return "", errors.New("public/private key mismatch")
	}
	return value.Address, nil
}
func run() error {
	action := flag.String("action", "", "protect, check, backup, restore")
	source := flag.String("source", "", "existing plaintext TEST-wallet basename")
	name := flag.String("name", "", "encrypted wallet basename")
	backup := flag.String("backup", "", "local encrypted-backup basename")
	flag.Parse()
	if *action != "protect" && *action != "check" && *action != "backup" && *action != "restore" {
		return errors.New("choose protect,check,backup,restore")
	}
	dir, err := directory("voin-encrypted-test-wallets")
	if err != nil {
		return err
	}
	path, err := pathFor(dir, *name)
	if err != nil {
		return err
	}
	var raw []byte
	if *action == "protect" {
		old, err := directory("voin-test-wallets")
		if err != nil {
			return err
		}
		oldPath, err := pathFor(old, *source)
		if err != nil {
			return err
		}
		raw, err = readPrivate(oldPath, store.MaxPlaintext)
		if err != nil {
			return err
		}
		defer store.Wipe(raw)
		address, err := validateKey(raw)
		if err != nil {
			return err
		}
		pass, err := password(true)
		if err != nil {
			return err
		}
		defer store.Wipe(pass)
		encrypted, err := store.Seal(raw, pass)
		if err != nil {
			return err
		}
		verified, err := store.Open(encrypted, pass)
		if err != nil {
			return err
		}
		equal := bytes.Equal(verified, raw)
		store.Wipe(verified)
		if !equal {
			return errors.New("encryption self-check failed")
		}
		if err := writeNew(path, encrypted); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"address": address, "encrypted_wallet": *name,
			"warning": "Original plaintext retained; old spending CLI still uses plaintext. Not production."})
	}
	backups, err := directory("voin-encrypted-test-backups")
	if err != nil {
		return err
	}
	backupPath := ""
	if *action == "backup" || *action == "restore" {
		backupPath, err = pathFor(backups, *backup)
		if err != nil {
			return err
		}
	}
	input := path
	if *action == "restore" {
		input = backupPath
	}
	raw, err = readPrivate(input, store.MaxEnvelope)
	if err != nil {
		return err
	}
	pass, err := password(false)
	if err != nil {
		return err
	}
	defer store.Wipe(pass)
	plain, err := store.Open(raw, pass)
	if err != nil {
		return err
	}
	defer store.Wipe(plain)
	address, err := validateKey(plain)
	if err != nil {
		return err
	}
	if *action == "backup" {
		if err := writeNew(backupPath, raw); err != nil {
			return err
		}
	}
	if *action == "restore" {
		if err := writeNew(path, raw); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"address": address, "action": *action,
		"warning": "Local encrypted copy only; no remote backup, 2FA, multisig or spending integration"})
}
