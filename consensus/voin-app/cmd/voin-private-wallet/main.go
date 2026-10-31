// Experimental Linux-only local test wallet. Private keys are NOT encrypted.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	voin "example.com/voin/abci"
	"flag"
	"fmt"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
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
	dir := filepath.Join(home, "voin-test-wallets")
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
func newWallet(name string) error {
	path, err := keyPath(name)
	if err != nil {
		return err
	}
	pk, sk, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	public, err := pk.MarshalBinary()
	if err != nil {
		return err
	}
	private, err := sk.MarshalBinary()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(public)
	wallet := walletFile{1, "voin_" + hex.EncodeToString(digest[:]),
		hex.EncodeToString(public), hex.EncodeToString(private)}
	data, err := json.Marshal(wallet)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
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
	return output(map[string]interface{}{"address": wallet.Address, "wallet": name,
		"warning": "UNENCRYPTED TEST KEY; never use real assets or upload key files"})
}
func readWallet(name string) (*walletFile, *mldsa44.PrivateKey, error) {
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
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 20000 {
		return nil, nil, errors.New("wallet must be a small regular 0600 file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 20001))
	if err != nil {
		return nil, nil, err
	}
	var wallet walletFile
	if err := json.Unmarshal(data, &wallet); err != nil {
		return nil, nil, err
	}
	public, err := hex.DecodeString(wallet.PublicKey)
	if err != nil || len(public) != mldsa44.PublicKeySize || wallet.Version != 1 {
		return nil, nil, errors.New("invalid test wallet")
	}
	digest := sha256.Sum256(public)
	if wallet.Address != "voin_"+hex.EncodeToString(digest[:]) {
		return nil, nil, errors.New("wallet address mismatch")
	}
	secret, err := hex.DecodeString(wallet.PrivateKey)
	if err != nil {
		return nil, nil, errors.New("invalid private key encoding")
	}
	var key mldsa44.PrivateKey
	if err := key.UnmarshalBinary(secret); err != nil {
		return nil, nil, errors.New("invalid private key")
	}
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
	name := flag.String("wallet", "", "basename in $HOME/voin-test-wallets")
	address := flag.String("address", "", "account address")
	to := flag.String("to", "", "recipient address")
	amount := flag.Uint64("amount", 0, "test units")
	hash := flag.String("hash", "", "transaction hash")
	flag.Parse()
	switch *action {
	case "new":
		return newWallet(*name)
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
		tx := voin.Transfer{Version: 1, ChainID: voin.ChainID, Sender: wallet.Address,
			Recipient: *to, Amount: *amount, Nonce: value.Nonce + 1}
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
