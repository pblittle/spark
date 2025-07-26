package grpctest

import (
	"log/slog"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcjson"
	_ "github.com/lightsparkdev/spark/so/ent/runtime"
	testutil "github.com/lightsparkdev/spark/test_util"
)

var faucet *testutil.Faucet

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn})))
	// Setup
	client, err := testutil.InitBitcoinClient()
	if err != nil {
		slog.Error("Error creating regtest client", "error", err)
		os.Exit(1)
	}

	faucet = testutil.GetFaucetInstance(client)
	btcjson.MustRegisterCmd("submitpackage", (*SubmitPackageCmd)(nil), btcjson.UsageFlag(0))

	// Run tests
	code := m.Run()

	client.Shutdown()

	// Teardown
	os.Exit(code)
}
