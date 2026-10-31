package voinapp

import (
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
)

func TestRecoveryAcrossProcesses(t *testing.T) {
	app := pendingApp(t)
	path := filepath.Join(t.TempDir(), "state.json")
	app.stateFile = path
	if _, err := app.Commit(
		context.Background(), &abci.CommitRequest{},
	); err != nil {
		t.Fatal(err)
	}
	trusted, err := app.StateHash()
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(
		ctx, executable, "-test.run=^TestRestoreChildProcess$", "-test.v",
	)
	cmd.Env = append(os.Environ(),
		"VOIN_RESTORE_TEST_CHILD=1",
		"VOIN_TEST_STATE_FILE="+path,
		"VOIN_TEST_HASH="+hex.EncodeToString(trusted[:]),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, output)
	}
	t.Log(string(output))

	expected := *app.state
	expected.Height = 2
	expectedHash, err := expected.Hash()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := NewAppFromCheckpoint(path, expectedHash)
	if err != nil {
		t.Fatal(err)
	}
	if restored.state.Height != 2 {
		t.Fatal("child did not persist the next block")
	}
}
