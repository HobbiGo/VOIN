// Experimental Linux-only encrypted TEST-wallet signer. Not production.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	voin "example.com/voin/abci"
	store "example.com/voin/abci/walletcrypto"
	"flag"
	"fmt"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"golang.org/x/term"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

type walletFile struct {
	Version    int    `json:"version"`
	Address    string `json:"address"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

var addressPattern = regexp.MustCompile(`^voin_[0-9a-f]{64}$`)
var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}$`)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func output(value interface{}) error { return json.NewEncoder(os.Stdout).Encode(value) }
func keyPath(name string) (string, error) {
	if !namePattern.MatchString(name) {
		return "", errors.New("invalid wallet filename")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "voin-encrypted-test-wallets")
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("wallet directory must be a private real directory (0700)")
	}
	return filepath.Join(dir, name), nil
}
func readWallet(name string) (*walletFile, *mldsa44.PrivateKey, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, nil, errors.New("interactive terminal required; no piped passwords")
	}
	path, err := keyPath(name)
	if err != nil {
		return nil, nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > store.MaxEnvelope {
		return nil, nil, errors.New("encrypted wallet must be a bounded regular0600 file")
	}
	encrypted, err := io.ReadAll(io.LimitReader(file, store.MaxEnvelope+1))
	if err != nil {
		return nil, nil, err
	}
	fmt.Fprint(os.Stderr, "Encrypted TEST wallet passphrase (input hidden): ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		store.Wipe(password)
		return nil, nil, err
	}
	defer store.Wipe(password)
	plain, err := store.Open(encrypted, password)
	if err != nil {
		return nil, nil, err
	}
	defer store.Wipe(plain)
	var wallet walletFile
	if err := json.Unmarshal(plain, &wallet); err != nil {
		return nil, nil, errors.New("invalid decrypted test wallet")
	}
	public, err := hex.DecodeString(wallet.PublicKey)
	if err != nil || len(public) != mldsa44.PublicKeySize || wallet.Version != 1 {
		return nil, nil, errors.New("invalid public key")
	}
	digest := sha256.Sum256(public)
	if wallet.Address != "voin_"+hex.EncodeToString(digest[:]) {
		return nil, nil, errors.New("wallet address mismatch")
	}
	secret, err := hex.DecodeString(wallet.PrivateKey)
	if err != nil || len(secret) != mldsa44.PrivateKeySize {
		return nil, nil, errors.New("invalid private key")
	}
	defer store.Wipe(secret)
	var key mldsa44.PrivateKey
	if err := key.UnmarshalBinary(secret); err != nil {
		return nil, nil, errors.New("invalid private key")
	}
	wallet.PrivateKey = ""
	return &wallet, &key, nil
}
func rpc(method string, params url.Values) (json.RawMessage, error) {
	client := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("redirect refused")
		}}
	response, err := client.Get("http://127.0.0.1:29657/" + method + "?" + params.Encode())
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 1024*1024 {
		return nil, errors.New("RPC response too large")
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("RPC HTTP %d: %.1000s", response.StatusCode, body)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.Error) != 0 && string(envelope.Error) != "null" {
		return nil, fmt.Errorf("RPC error: %.1000s", envelope.Error)
	}
	if len(envelope.Result) == 0 {
		return nil, errors.New("missing RPC result")
	}
	return envelope.Result, nil
}
func account(address string) (voin.Account, string, error) {
	var zero voin.Account
	if !addressPattern.MatchString(address) {
		return zero, "", errors.New("invalid address")
	}
	raw, err := rpc("abci_query", url.Values{"path": {`"/account"`},
		"data": {"0x" + hex.EncodeToString([]byte(address))}, "prove": {"false"}})
	if err != nil {
		return zero, "", err
	}
	var result struct {
		Response struct {
			Code   uint32 `json:"code"`
			Log    string `json:"log"`
			Value  string `json:"value"`
			Height string `json:"height"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return zero, "", err
	}
	if result.Response.Code != 0 {
		return zero, "", errors.New(result.Response.Log)
	}
	value, err := base64.StdEncoding.DecodeString(result.Response.Value)
	if err != nil {
		return zero, "", err
	}
	if err := json.Unmarshal(value, &zero); err != nil {
		return zero, "", err
	}
	return zero, result.Response.Height, nil
}
func run() error {
	action := flag.String("action", "", "new, balance, send, status")
	name := flag.String("wallet", "", "basename in $HOME/voin-encrypted-test-wallets")
	address := flag.String("address", "", "account address")
	to := flag.String("to", "", "recipient address")
	amount := flag.Uint64("amount", 0, "test units")
	hash := flag.String("hash", "", "transaction hash")
	flag.Parse()
	switch *action {
	case "new":
		return errors.New("create/protect via storage tool; no plaintext key creation here")
	case "balance":
		value, height, err := account(*address)
		if err != nil {
			return err
		}
		return output(map[string]interface{}{"address": *address, "balance": value.Balance,
			"nonce": value.Nonce, "height": height, "proof_verified": false})
	case "send":
		wallet, sk, err := readWallet(*name)
		if err != nil {
			return err
		}
		value, _, err := account(wallet.Address)
		if err != nil {
			return err
		}
		if value.Nonce == ^uint64(0) || *amount == 0 || *amount > value.Balance {
			return errors.New("invalid amount, balance or nonce")
		}
		if !addressPattern.MatchString(*to) || *to == wallet.Address {
			return errors.New("invalid or identical recipient")
		}
		tx := voin.Transfer{Version: 1, ChainID: voin.ChainID, Sender: wallet.Address,
			Recipient: *to, Amount: *amount, Nonce: value.Nonce + 1}
		if err := confirmTransfer(os.Stdin, os.Stderr, tx); err != nil {
			return err
		}
		message, err := json.Marshal(tx)
		if err != nil {
			return err
		}
		sig := make([]byte, mldsa44.SignatureSize)
		if err := mldsa44.SignTo(sk, message, []byte("VOIN/transfer/v1"), false, sig); err != nil {
			return err
		}
		raw, err := json.Marshal(voin.SignedTransfer{Transfer: tx,
			PublicKey: wallet.PublicKey, Signature: hex.EncodeToString(sig)})
		if err != nil {
			return err
		}
		if _, err := voin.VerifyTransfer(raw); err != nil {
			return err
		}
		submitted, err := rpc("broadcast_tx_sync", url.Values{"tx": {"0x" + hex.EncodeToString(raw)}})
		if err != nil {
			return err
		}
		var result struct {
			Code uint32 `json:"code"`
			Log  string `json:"log"`
		}
		if err := json.Unmarshal(submitted, &result); err != nil {
			return err
		}
		if result.Code != 0 {
			return errors.New(result.Log)
		}
		digest := sha256.Sum256(raw)
		return output(map[string]interface{}{"hash": strings.ToUpper(hex.EncodeToString(digest[:])),
			"status": "submitted_not_confirmed", "nonce": tx.Nonce})
	case "status":
		decoded, err := hex.DecodeString(*hash)
		if err != nil || len(decoded) != 32 {
			return errors.New("invalid transaction hash")
		}
		raw, err := rpc("tx", url.Values{"hash": {"0x" + hex.EncodeToString(decoded)}, "prove": {"false"}})
		if err != nil {
			return err
		}
		var result struct {
			Height   string `json:"height"`
			TxResult struct {
				Code uint32 `json:"code"`
			} `json:"tx_result"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			return err
		}
		return output(map[string]interface{}{"hash": strings.ToUpper(*hash), "height": result.Height,
			"code": result.TxResult.Code, "proof_verified": false})
	default:
		return errors.New("choose -action new, balance, send or status")
	}
}

// This is local consent, not 2FA/multisig. No signature is created before consent.
func confirmTransfer(input io.Reader, output io.Writer, tx voin.Transfer) error {
	fmt.Fprintf(output, "\nTEST TRANSFER ONLY\nNetwork: %s\nFrom: %s\nTo: %s\nAmount: %d test units\nNonce: %d\nType KIRIM then Enter to sign and submit, anything else cancels: ",
		tx.ChainID, tx.Sender, tx.Recipient, tx.Amount, tx.Nonce)
	line, err := bufio.NewReader(io.LimitReader(input, 128)).ReadString('\n')
	if err != nil {
		return errors.New("confirmation cancelled")
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if line != "KIRIM" {
		return errors.New("confirmation cancelled; no transaction signed")
	}
	return nil
}
