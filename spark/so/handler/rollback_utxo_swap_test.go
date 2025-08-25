//go:build gripmock
// +build gripmock

package handler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/distributed-lab/gripmock"
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbinternal "github.com/lightsparkdev/spark/proto/spark_internal"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
)

func TestRollbackUtxoSwap_InvalidStatement(t *testing.T) {
	defer func() {
		_ = gripmock.Clear()
	}()

	ctx, sessionCtx := setupPgTestContext(t)
	defer sessionCtx.Close()

	cfg := setupTestConfigWithRegtestNoAuthz(t)
	handler := NewInternalDepositHandler(cfg)

	// Create request with invalid signature
	req := &pbinternal.RollbackUtxoSwapRequest{
		OnChainUtxo: &pb.UTXO{
			Txid:    []byte("test_txid"),
			Vout:    0,
			Network: pb.Network_REGTEST,
		},
		Signature:            []byte("invalid_signature"),
		CoordinatorPublicKey: cfg.IdentityPublicKey().Serialize(),
	}

	_, err := handler.RollbackUtxoSwap(ctx, cfg, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
}

func TestRollbackUtxoSwap_UtxoDoesNotExist(t *testing.T) {
	ctx, sessionCtx := setupPgTestContext(t)
	defer sessionCtx.Close()

	cfg := setupTestConfigWithRegtestNoAuthz(t)
	handler := NewInternalDepositHandler(cfg)

	// Generate valid rollback request for non-existent UTXO
	nonExistentTxid := []byte("nonexistent_txid_for_testing_12345")
	rollbackRequest, err := GenerateRollbackStaticDepositUtxoSwapForUtxoRequest(ctx, cfg, &pb.UTXO{
		Txid:    nonExistentTxid,
		Vout:    0,
		Network: pb.Network_REGTEST,
	})
	require.NoError(t, err)

	_, err = handler.RollbackUtxoSwap(ctx, cfg, rollbackRequest)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRollbackUtxoSwap_NoErrorIfUtxoSwapDoesNotExist(t *testing.T) {
	defer func() {
		_ = gripmock.Clear()
	}()

	err := gripmock.AddStub("spark_internal.SparkInternalService", "rollback_utxo_swap", nil, nil)
	require.NoError(t, err)

	ctx, sessionCtx := setupPgTestContext(t)
	defer sessionCtx.Close()

	cfg := setupTestConfigWithRegtestNoAuthz(t)
	handler := NewInternalDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	_, ownerIdentityPub := generateFixedKeyPair(1)
	_, ownerSigningPub := generateFixedKeyPair(2)

	keyshare := createTestSigningKeyshare(t, ctx, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPub, ownerSigningPub)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	// Don't create UtxoSwap - it doesn't exist
	rollbackRequest, err := GenerateRollbackStaticDepositUtxoSwapForUtxoRequest(ctx, cfg, &pb.UTXO{
		Txid:    utxo.Txid,
		Vout:    uint32(utxo.Vout),
		Network: pb.Network_REGTEST,
	})
	require.NoError(t, err)

	_, err = handler.RollbackUtxoSwap(ctx, cfg, rollbackRequest)
	assert.NoError(t, err) // Should not error if UtxoSwap doesn't exist
}

func TestRollbackUtxoSwap_NoErrorIfUtxoSwapCancelled(t *testing.T) {
	defer func() {
		_ = gripmock.Clear()
	}()

	err := gripmock.AddStub("spark_internal.SparkInternalService", "rollback_utxo_swap", nil, nil)
	require.NoError(t, err)

	ctx, sessionCtx := setupPgTestContext(t)
	defer sessionCtx.Close()

	cfg := setupTestConfigWithRegtestNoAuthz(t)
	handler := NewInternalDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	_, ownerIdentityPub := generateFixedKeyPair(1)
	_, ownerSigningPub := generateFixedKeyPair(2)

	keyshare := createTestSigningKeyshare(t, ctx, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPub, ownerSigningPub)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	// Create cancelled UtxoSwap
	_ = createTestUtxoSwap(t, ctx, sessionCtx.Client, utxo, st.UtxoSwapStatusCancelled)

	rollbackRequest, err := GenerateRollbackStaticDepositUtxoSwapForUtxoRequest(ctx, cfg, &pb.UTXO{
		Txid:    utxo.Txid,
		Vout:    uint32(utxo.Vout),
		Network: pb.Network_REGTEST,
	})
	require.NoError(t, err)

	_, err = handler.RollbackUtxoSwap(ctx, cfg, rollbackRequest)
	assert.NoError(t, err) // Should not error for cancelled UtxoSwap
}

func TestRollbackUtxoSwap_NoErrorIfUtxoSwapCreated(t *testing.T) {
	defer func() {
		_ = gripmock.Clear()
	}()

	err := gripmock.AddStub("spark_internal.SparkInternalService", "rollback_utxo_swap", nil, nil)
	require.NoError(t, err)

	ctx, sessionCtx := setupPgTestContext(t)
	defer sessionCtx.Close()

	cfg := setupTestConfigWithRegtestNoAuthz(t)
	handler := NewInternalDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	_, ownerIdentityPub := generateFixedKeyPair(1)
	_, ownerSigningPub := generateFixedKeyPair(2)

	keyshare := createTestSigningKeyshare(t, ctx, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPub, ownerSigningPub)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	utxoSwap, err := sessionCtx.Client.UtxoSwap.Create().
		SetStatus(st.UtxoSwapStatusCreated).
		SetUtxo(utxo).
		SetRequestType(st.UtxoSwapRequestTypeRefund).
		SetCreditAmountSats(10000).
		SetSspSignature([]byte("test_ssp_signature")).
		SetSspIdentityPublicKey(ownerIdentityPub).
		SetUserIdentityPublicKey(ownerIdentityPub).
		SetCoordinatorIdentityPublicKey(cfg.IdentityPublicKey().Serialize()).
		Save(ctx)
	require.NoError(t, err)

	rollbackRequest, err := GenerateRollbackStaticDepositUtxoSwapForUtxoRequest(ctx, cfg, &pb.UTXO{
		Txid:    utxo.Txid,
		Vout:    uint32(utxo.Vout),
		Network: pb.Network_REGTEST,
	})
	require.NoError(t, err)

	_, err = handler.RollbackUtxoSwap(ctx, cfg, rollbackRequest)
	assert.NoError(t, err)

	// Commit tx before checking the result
	tx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)
	err = tx.Commit()
	require.NoError(t, err)

	// Verify UtxoSwap is now cancelled (use fresh context)
	updatedUtxoSwap, err := sessionCtx.Client.UtxoSwap.Get(t.Context(), utxoSwap.ID)
	require.NoError(t, err)
	assert.Equal(t, st.UtxoSwapStatusCancelled, updatedUtxoSwap.Status)
}

func TestRollbackUtxoSwap_ErrorIfUtxoSwapCompleted(t *testing.T) {
	ctx, sessionCtx := setupPgTestContext(t)
	defer sessionCtx.Close()

	cfg := setupTestConfigWithRegtestNoAuthz(t)
	handler := NewInternalDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	_, ownerIdentityPub := generateFixedKeyPair(1)
	_, ownerSigningPub := generateFixedKeyPair(2)

	keyshare := createTestSigningKeyshare(t, ctx, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPub, ownerSigningPub)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	// Create completed UtxoSwap
	_, err := sessionCtx.Client.UtxoSwap.Create().
		SetStatus(st.UtxoSwapStatusCompleted).
		SetUtxo(utxo).
		SetRequestType(st.UtxoSwapRequestTypeRefund).
		SetCreditAmountSats(10000).
		SetSspSignature([]byte("test_ssp_signature")).
		SetSspIdentityPublicKey(ownerIdentityPub).
		SetUserIdentityPublicKey(ownerIdentityPub).
		SetCoordinatorIdentityPublicKey(cfg.IdentityPublicKey().Serialize()).
		Save(ctx)
	require.NoError(t, err)

	rollbackRequest, err := GenerateRollbackStaticDepositUtxoSwapForUtxoRequest(ctx, cfg, &pb.UTXO{
		Txid:    utxo.Txid,
		Vout:    uint32(utxo.Vout),
		Network: pb.Network_REGTEST,
	})
	require.NoError(t, err)

	_, err = handler.RollbackUtxoSwap(ctx, cfg, rollbackRequest)
	assert.Error(t, err)

	// Check that error message contains "completed"
	if err != nil {
		assert.Contains(t, err.Error(), "completed")
	}
}
