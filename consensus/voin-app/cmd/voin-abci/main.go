package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	voinapp "example.com/voin/abci"
	abciserver "github.com/cometbft/cometbft/abci/server"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	path := flag.String("state", "", "absolute state file path")
	checkpoint := flag.String("checkpoint", "", "trusted state hash in hex")
	flag.Parse()

	var app *voinapp.App
	var err error
	if *checkpoint == "" {
		app, err = voinapp.NewFreshPersistentApp(*path)
	} else {
		raw, decodeErr := hex.DecodeString(*checkpoint)
		if decodeErr != nil || len(raw) != 32 {
			return fmt.Errorf("checkpoint must contain 32 bytes in hex")
		}
		var trusted [32]byte
		copy(trusted[:], raw)
		app, err = voinapp.NewAppFromCheckpoint(*path, trusted)
	}
	if err != nil {
		return err
	}

	server, err := abciserver.NewServer(
		"tcp://127.0.0.1:27658", "socket", app,
	)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(
		context.Background(), os.Interrupt, syscall.SIGTERM,
	)
	defer cancel()

	if err := server.Start(); err != nil {
		return err
	}
	fmt.Println("VOIN experimental ABCI: 127.0.0.1:27658")
	fmt.Println("Transactions disabled; empty blocks only")
	<-ctx.Done()

	if err := server.Stop(); err != nil {
		return err
	}
	return nil
}
