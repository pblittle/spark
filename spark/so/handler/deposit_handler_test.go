package handler

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/ent/schema/schematype"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestVerifiedTargetUtxo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, dbCtx := db.NewTestSQLiteContext(t, ctx)
	defer dbCtx.Close()

	tx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)

	// Create test data
	blockHeight := 100
	txid := []byte("test_txid")
	vout := uint32(0)

	// Create block height records for both networks
	_, err = tx.BlockHeight.Create().
		SetNetwork(st.NetworkMainnet).
		SetHeight(int64(blockHeight)).
		Save(ctx)
	require.NoError(t, err)

	_, err = tx.BlockHeight.Create().
		SetNetwork(st.NetworkRegtest).
		SetHeight(int64(blockHeight)).
		Save(ctx)
	require.NoError(t, err)

	t.Run("successful verification", func(t *testing.T) {
		config := &so.Config{
			BitcoindConfigs: map[string]so.BitcoindConfig{
				"regtest": {
					DepositConfirmationThreshold: 1,
				},
			},
		}
		require.Equal(t, "regtest", strings.ToLower(string(schematype.NetworkRegtest)))

		// Create signing keyshare first
		signingKeyshare, err := tx.SigningKeyshare.Create().
			SetStatus(st.KeyshareStatusAvailable).
			SetSecretShare([]byte("test_secret_share")).
			SetPublicShares(map[string][]byte{"test": []byte("test_public_share")}).
			SetPublicKey([]byte("test_public_key")).
			SetMinSigners(2).
			SetCoordinatorIndex(0).
			Save(ctx)
		require.NoError(t, err)

		// Create deposit address
		depositAddress, err := tx.DepositAddress.Create().
			SetAddress("test_address").
			SetOwnerIdentityPubkey([]byte("test_identity_pubkey")).
			SetOwnerSigningPubkey([]byte("test_signing_pubkey")).
			SetSigningKeyshare(signingKeyshare).
			Save(ctx)
		require.NoError(t, err)

		// Create UTXO with sufficient confirmations
		utxoBlockHeight := blockHeight - int(config.BitcoindConfigs["regtest"].DepositConfirmationThreshold) + 1
		utxo, err := tx.Utxo.Create().
			SetNetwork(st.NetworkRegtest).
			SetTxid(txid).
			SetVout(vout).
			SetBlockHeight(int64(utxoBlockHeight)).
			SetAmount(1000).
			SetPkScript([]byte("test_script")).
			SetDepositAddress(depositAddress).
			Save(ctx)
		require.NoError(t, err)

		// Test verification
		verifiedUtxo, err := VerifiedTargetUtxo(ctx, config, tx, st.NetworkRegtest, txid, vout)
		require.NoError(t, err)
		assert.Equal(t, utxo.ID, verifiedUtxo.ID)
		assert.Equal(t, utxo.BlockHeight, verifiedUtxo.BlockHeight)

		// Test verification in mainnet (should fail)
		_, err = VerifiedTargetUtxo(ctx, config, tx, st.NetworkMainnet, txid, vout)
		require.ErrorContains(t, err, "utxo not found")
	})

	t.Run("insufficient confirmations", func(t *testing.T) {
		config := &so.Config{
			BitcoindConfigs: map[string]so.BitcoindConfig{
				"regtest": {
					DepositConfirmationThreshold: 1,
				},
			},
		}

		// Create signing keyshare first
		signingKeyshare, err := tx.SigningKeyshare.Create().
			SetStatus(st.KeyshareStatusAvailable).
			SetSecretShare([]byte("test_secret_share2")).
			SetPublicShares(map[string][]byte{"test": []byte("test_public_share2")}).
			SetPublicKey([]byte("test_public_key2")).
			SetMinSigners(2).
			SetCoordinatorIndex(0).
			Save(ctx)
		require.NoError(t, err)

		// Create deposit address
		depositAddress, err := tx.DepositAddress.Create().
			SetAddress("test_address2").
			SetOwnerIdentityPubkey([]byte("test_identity_pubkey2")).
			SetOwnerSigningPubkey([]byte("test_signing_pubkey2")).
			SetSigningKeyshare(signingKeyshare).
			Save(ctx)
		require.NoError(t, err)

		// Test verification with not yet mined utxo
		_, err = VerifiedTargetUtxo(ctx, config, tx, st.NetworkRegtest, []byte("test_txid2"), 1)
		require.Error(t, err)
		grpcError, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, grpcError.Code())
		assert.Equal(t, fmt.Sprintf("utxo not found: txid: %s vout: 1", hex.EncodeToString([]byte("test_txid2"))), grpcError.Message())

		// Create UTXO with insufficient confirmations
		utxoBlockHeight := blockHeight - int(config.BitcoindConfigs["regtest"].DepositConfirmationThreshold) + 2
		_, err = tx.Utxo.Create().
			SetNetwork(st.NetworkRegtest).
			SetTxid([]byte("test_txid2")).
			SetVout(1).
			SetBlockHeight(int64(utxoBlockHeight)).
			SetAmount(1000).
			SetPkScript([]byte("test_script")).
			SetDepositAddress(depositAddress).
			Save(ctx)
		require.NoError(t, err)

		// Test verification
		_, err = VerifiedTargetUtxo(ctx, config, tx, st.NetworkRegtest, []byte("test_txid2"), 1)
		require.Error(t, err)
		assert.ErrorContains(t, err, "deposit tx doesn't have enough confirmations")
	})
}
