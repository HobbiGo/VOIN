package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	abciclient "github.com/cometbft/cometbft/abci/client"
	abci "github.com/cometbft/cometbft/abci/types"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	client, err := abciclient.NewClient(
		"tcp://127.0.0.1:27658", "socket", true,
	)
	if err != nil {
		return err
	}
	if err := client.Start(); err != nil {
		return err
	}
	defer client.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	info, err := client.Info(ctx, &abci.InfoRequest{})
	if err != nil {
		return err
	}
	if info == nil || info.LastBlockHeight < 1 ||
		len(info.LastBlockAppHash) != 32 {
		return fmt.Errorf("no valid committed checkpoint available")
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Height int64  `json:"height"`
		Hash   string `json:"hash"`
	}{
		Height: info.LastBlockHeight,
		Hash:   hex.EncodeToString(info.LastBlockAppHash),
	})
}
