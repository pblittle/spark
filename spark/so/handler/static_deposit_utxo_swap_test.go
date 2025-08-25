//go:build gripmock
// +build gripmock

package handler

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/distributed-lab/gripmock"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
)

func createValidTaprootSignature() []byte {
	privKeyBytes, _ := generateFixedKeyPair(1)

	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	taprootKey := txscript.TweakTaprootPrivKey(*privKey, []byte{})

	messageHex := "e6831dc8177700874fe8d8fade0ed4574a6b52d76648f22d7808fc12925d1626"
	messageBytes, _ := hex.DecodeString(messageHex)

	sig, err := schnorr.Sign(taprootKey, messageBytes)
	if err != nil {
		panic(fmt.Sprintf("failed to create schnorr signature: %v", err))
	}

	sigBytes := sig.Serialize()

	return sigBytes
}

func TestInitiateStaticDepositUtxoSwap_ErrorWithNonOwnedTransferLeaves(t *testing.T) {
	defer func() {
		_ = gripmock.Clear()
	}()

	swapSuccessStub := map[string]interface{}{
		"UtxoDepositAddress": "bc1ptest_static_deposit_address_for_testing",
	}
	err := gripmock.AddStub("spark_internal.SparkInternalService", "create_static_deposit_utxo_swap", nil, swapSuccessStub)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round1", nil, frostRound1StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round2", nil, frostRound2StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "rollback_utxo_swap", nil, nil)
	require.NoError(t, err)

	ctx, sessionCtx := setupPgTestContext(t)
	defer sessionCtx.Close()

	cfg := setupTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	ownerIdentityPrivKey, ownerIdentityPub := generateFixedKeyPair(1)
	_, ownerSigningPub := generateFixedKeyPair(2)
	_, differentOwnerPub := generateFixedKeyPair(99) // Different owner

	keyshare := createTestSigningKeyshare(t, ctx, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPub, ownerSigningPub)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	tree := createTestTreeForClaim(t, ctx, sessionCtx.Client)
	leaf := createTestTreeNodeForStaticDeposit(t, ctx, sessionCtx.Client, tree, keyshare, differentOwnerPub) // Leaf owned by different user

	spendTxBytes := createValidBitcoinTxBytes(ownerIdentityPub)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(
		t, cfg, utxo, leaf,
		ownerIdentityPrivKey, ownerIdentityPub, ownerSigningPub,
		testSspSignature, spendTxBytes,
	)

	_, err = handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "is not owned by sender")
}

func TestInitiateStaticDepositUtxoSwap_ErrorIfUtxoNotToStaticDepositAddress(t *testing.T) {
	defer func() {
		_ = gripmock.Clear()
	}()

	swapSuccessStub := map[string]interface{}{
		"UtxoDepositAddress": "bc1ptest_static_deposit_address_for_testing",
	}
	err := gripmock.AddStub("spark_internal.SparkInternalService", "create_static_deposit_utxo_swap", nil, swapSuccessStub)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round1", nil, frostRound1StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round2", nil, frostRound2StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "rollback_utxo_swap", nil, nil)
	require.NoError(t, err)

	ctx, sessionCtx := setupPgTestContext(t)
	defer sessionCtx.Close()

	cfg := setupTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	ownerIdentityPrivKey, ownerIdentityPub := generateFixedKeyPair(1)
	_, ownerSigningPub := generateFixedKeyPair(2)

	keyshare := createTestSigningKeyshare(t, ctx, sessionCtx.Client)

	// Create non-static deposit address
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPub, ownerSigningPub)
	depositAddress, err = sessionCtx.Client.DepositAddress.UpdateOne(depositAddress).SetIsStatic(false).Save(ctx)
	require.NoError(t, err)

	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	tree := createTestTreeForClaim(t, ctx, sessionCtx.Client)
	leaf := createTestTreeNodeForStaticDeposit(t, ctx, sessionCtx.Client, tree, keyshare, ownerIdentityPub)

	spendTxBytes := createValidBitcoinTxBytes(ownerIdentityPub)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(
		t, cfg, utxo, leaf,
		ownerIdentityPrivKey, ownerIdentityPub, ownerSigningPub,
		testSspSignature, spendTxBytes,
	)

	_, err = handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to claim a deposit to a non-static address")
}

func TestInitiateStaticDepositUtxoSwap_UtxoNotConfirmed(t *testing.T) {
	ctx, sessionCtx := setupPgTestContext(t)
	defer sessionCtx.Close()

	cfg := setupTestConfigWithRegtestNoAuthz(t)
	cfg.BitcoindConfigs["regtest"] = so.BitcoindConfig{
		DepositConfirmationThreshold: 100,
	}

	handler := NewStaticDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 150)

	ownerIdentityPrivKey, ownerIdentityPub := generateFixedKeyPair(1)
	_, ownerSigningPub := generateFixedKeyPair(2)

	keyshare := createTestSigningKeyshare(t, ctx, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPub, ownerSigningPub)

	// confirmations = currentBlockHeight - utxoBlockHeight + 1
	// Needed: 150 - utxoBlockHeight + 1 < 100 => utxoBlockHeight > 51
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 52) // only 99 confirmations

	tree := createTestTreeForClaim(t, ctx, sessionCtx.Client)
	leaf := createTestTreeNode(t, ctx, sessionCtx.Client, tree, keyshare)

	spendTxBytes := createValidBitcoinTxBytes(ownerIdentityPub)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(
		t, cfg, utxo, leaf,
		ownerIdentityPrivKey, ownerIdentityPub, ownerSigningPub,
		testSspSignature, spendTxBytes,
	)

	_, err := handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "confirmations")
}

func TestInitiateStaticDepositUtxoSwap_ErrorIfUtxoSwapAlreadyInProgress(t *testing.T) {
	ctx, sessionCtx := setupPgTestContext(t)
	defer sessionCtx.Close()

	cfg := setupTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	ownerIdentityPrivKey, ownerIdentityPub := generateFixedKeyPair(1)
	_, ownerSigningPub := generateFixedKeyPair(2)

	keyshare := createTestSigningKeyshare(t, ctx, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPub, ownerSigningPub)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	// Create existing UTXO swap in progress
	_ = createTestUtxoSwap(t, ctx, sessionCtx.Client, utxo, st.UtxoSwapStatusCreated)

	tree := createTestTreeForClaim(t, ctx, sessionCtx.Client)
	leaf := createTestTreeNodeForStaticDeposit(t, ctx, sessionCtx.Client, tree, keyshare, ownerIdentityPub)

	spendTxBytes := createValidBitcoinTxBytes(ownerIdentityPub)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(
		t, cfg, utxo, leaf,
		ownerIdentityPrivKey, ownerIdentityPub, ownerSigningPub,
		testSspSignature, spendTxBytes,
	)

	_, err := handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "utxo swap is already registered")
}

func TestInitiateStaticDepositUtxoSwap_ErrorIfUtxoSwapAlreadyCompleted(t *testing.T) {
	ctx, sessionCtx := setupPgTestContext(t)
	defer sessionCtx.Close()

	cfg := setupTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	ownerIdentityPrivKey, ownerIdentityPub := generateFixedKeyPair(1)
	_, ownerSigningPub := generateFixedKeyPair(2)

	keyshare := createTestSigningKeyshare(t, ctx, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPub, ownerSigningPub)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	// Create existing completed UTXO swap
	_ = createTestUtxoSwap(t, ctx, sessionCtx.Client, utxo, st.UtxoSwapStatusCompleted)

	tree := createTestTreeForClaim(t, ctx, sessionCtx.Client)
	leaf := createTestTreeNodeForStaticDeposit(t, ctx, sessionCtx.Client, tree, keyshare, ownerIdentityPub)

	spendTxBytes := createValidBitcoinTxBytes(ownerIdentityPub)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(
		t, cfg, utxo, leaf,
		ownerIdentityPrivKey, ownerIdentityPub, ownerSigningPub,
		testSspSignature, spendTxBytes,
	)

	_, err := handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "utxo swap is already registered")
}

func TestInitiateStaticDepositUtxoSwap_CanCreateWithPreviousFailedRefund(t *testing.T) {
	defer func() {
		_ = gripmock.Clear()
	}()

	swapSuccessStub := map[string]interface{}{
		"UtxoDepositAddress": "bc1ptest_static_deposit_address_for_testing",
	}
	err := gripmock.AddStub("spark_internal.SparkInternalService", "create_static_deposit_utxo_swap", nil, swapSuccessStub)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "initiate_transfer", nil, nil)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round1", nil, frostRound1StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round2", nil, frostRound2StubOutput)
	require.NoError(t, err)

	aggregateFrostStubOutput := map[string]interface{}{
		"signature": createValidTaprootSignature(),
	}
	err = gripmock.AddStub("frost.FrostService", "aggregate_frost", nil, aggregateFrostStubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "utxo_swap_completed", nil, nil)
	require.NoError(t, err)

	ctx, sessionCtx := setupPgTestContext(t)
	defer sessionCtx.Close()

	cfg := setupTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	ownerIdentityPrivKey, ownerIdentityPub := generateFixedKeyPair(1)
	_, ownerSigningPub := generateFixedKeyPair(2)

	keyshare := createTestSigningKeyshare(t, ctx, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPub, ownerSigningPub)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	// Create previous failed refund UtxoSwap
	previousUtxoSwap, err := sessionCtx.Client.UtxoSwap.Create().
		SetStatus(st.UtxoSwapStatusCancelled).
		SetRequestType(st.UtxoSwapRequestTypeRefund).
		SetUserIdentityPublicKey(ownerIdentityPub).
		SetCoordinatorIdentityPublicKey(cfg.IdentityPublicKey().Serialize()).
		SetUtxo(utxo).
		Save(ctx)
	require.NoError(t, err)

	tree := createTestTreeForClaim(t, ctx, sessionCtx.Client)
	leaf := createTestTreeNodeForStaticDeposit(t, ctx, sessionCtx.Client, tree, keyshare, ownerIdentityPub)

	spendTxBytes := createValidBitcoinTxBytes(ownerIdentityPub)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(
		t, cfg, utxo, leaf,
		ownerIdentityPrivKey, ownerIdentityPub, ownerSigningPub,
		testSspSignature, spendTxBytes,
	)

	resp, err := handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Commit tx before checking the result
	tx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)
	err = tx.Commit()
	require.NoError(t, err)

	// Verify previous UtxoSwap still exists with cancelled status
	updatedPreviousSwap, err := sessionCtx.Client.UtxoSwap.Get(t.Context(), previousUtxoSwap.ID)
	require.NoError(t, err)
	assert.Equal(t, st.UtxoSwapStatusCancelled, updatedPreviousSwap.Status)

	// Verify new UtxoSwap was created
	allSwaps, err := sessionCtx.Client.UtxoSwap.Query().All(t.Context())
	require.NoError(t, err)
	assert.Greater(t, len(allSwaps), 1, "New UtxoSwap should be created despite previous failed refund")
}

func TestInitiateStaticDepositUtxoSwap_CanCreateWithPreviousFailedClaim(t *testing.T) {
	defer func() {
		_ = gripmock.Clear()
	}()

	swapSuccessStub := map[string]interface{}{
		"UtxoDepositAddress": "bc1ptest_static_deposit_address_for_testing",
	}
	err := gripmock.AddStub("spark_internal.SparkInternalService", "create_static_deposit_utxo_swap", nil, swapSuccessStub)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "initiate_transfer", nil, nil)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round1", nil, frostRound1StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round2", nil, frostRound2StubOutput)
	require.NoError(t, err)

	aggregateFrostStubOutput := map[string]interface{}{
		"signature": createValidTaprootSignature(),
	}
	err = gripmock.AddStub("frost.FrostService", "aggregate_frost", nil, aggregateFrostStubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "utxo_swap_completed", nil, nil)
	require.NoError(t, err)

	ctx, sessionCtx := setupPgTestContext(t)
	defer sessionCtx.Close()

	cfg := setupTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	ownerIdentityPrivKey, ownerIdentityPub := generateFixedKeyPair(1)
	_, ownerSigningPub := generateFixedKeyPair(2)

	keyshare := createTestSigningKeyshare(t, ctx, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPub, ownerSigningPub)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	// Create previous failed claim UtxoSwap
	previousUtxoSwap, err := sessionCtx.Client.UtxoSwap.Create().
		SetStatus(st.UtxoSwapStatusCancelled).
		SetRequestType(st.UtxoSwapRequestTypeFixedAmount).
		SetUserIdentityPublicKey(ownerIdentityPub).
		SetCoordinatorIdentityPublicKey(cfg.IdentityPublicKey().Serialize()).
		SetUtxo(utxo).
		Save(ctx)
	require.NoError(t, err)

	tree := createTestTreeForClaim(t, ctx, sessionCtx.Client)
	leaf := createTestTreeNodeForStaticDeposit(t, ctx, sessionCtx.Client, tree, keyshare, ownerIdentityPub)

	spendTxBytes := createValidBitcoinTxBytes(ownerIdentityPub)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(
		t, cfg, utxo, leaf,
		ownerIdentityPrivKey, ownerIdentityPub, ownerSigningPub,
		testSspSignature, spendTxBytes,
	)

	resp, err := handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Commit tx before checking the result
	tx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)
	err = tx.Commit()
	require.NoError(t, err)

	// Verify previous UtxoSwap still exists with cancelled status
	updatedPreviousSwap, err := sessionCtx.Client.UtxoSwap.Get(t.Context(), previousUtxoSwap.ID)
	require.NoError(t, err)
	assert.Equal(t, st.UtxoSwapStatusCancelled, updatedPreviousSwap.Status)

	// Verify new UtxoSwap was created
	allSwaps, err := sessionCtx.Client.UtxoSwap.Query().All(t.Context())
	require.NoError(t, err)
	assert.Greater(t, len(allSwaps), 1, "New UtxoSwap should be created despite previous failed claim")
}

func TestInitiateStaticDepositUtxoSwap_TransferFailureCancelsUtxoSwap(t *testing.T) {
	defer func() {
		_ = gripmock.Clear()
	}()

	swapSuccessStub := map[string]interface{}{
		"UtxoDepositAddress": "bc1ptest_static_deposit_address_for_testing",
	}
	err := gripmock.AddStub("spark_internal.SparkInternalService", "create_static_deposit_utxo_swap", nil, swapSuccessStub)
	require.NoError(t, err)

	// Mock transfer failure
	transferFailureStub := map[string]interface{}{
		"error": "Failed to create transfer",
	}
	err = gripmock.AddStub("spark_internal.SparkInternalService", "initiate_transfer", nil, transferFailureStub)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round1", nil, frostRound1StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round2", nil, frostRound2StubOutput)
	require.NoError(t, err)

	// Mock rollback success
	err = gripmock.AddStub("spark_internal.SparkInternalService", "rollback_utxo_swap", nil, nil)
	require.NoError(t, err)

	ctx, sessionCtx := setupPgTestContext(t)
	defer sessionCtx.Close()

	cfg := setupTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	ownerIdentityPrivKey, ownerIdentityPub := generateFixedKeyPair(1)
	_, ownerSigningPub := generateFixedKeyPair(2)

	keyshare := createTestSigningKeyshare(t, ctx, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPub, ownerSigningPub)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	tree := createTestTreeForClaim(t, ctx, sessionCtx.Client)
	leaf := createTestTreeNodeForStaticDeposit(t, ctx, sessionCtx.Client, tree, keyshare, ownerIdentityPub)

	spendTxBytes := createValidBitcoinTxBytes(ownerIdentityPub)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(
		t, cfg, utxo, leaf,
		ownerIdentityPrivKey, ownerIdentityPub, ownerSigningPub,
		testSspSignature, spendTxBytes,
	)

	_, err = handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create transfer")

	// Verify UtxoSwap was created initially but then cancelled due to transfer failure
	utxoSwaps, err := sessionCtx.Client.UtxoSwap.Query().All(ctx)
	require.NoError(t, err)

	if len(utxoSwaps) > 0 {
		// If UtxoSwap was created, it should be cancelled
		utxoSwap := utxoSwaps[0]
		assert.Equal(t, st.UtxoSwapStatusCancelled, utxoSwap.Status)
	}
}

func TestInitiateStaticDepositUtxoSwap_ErrorIfWrongVerificationKey(t *testing.T) {
	defer func() {
		_ = gripmock.Clear()
	}()

	swapSuccessStub := map[string]interface{}{
		"UtxoDepositAddress": "bc1ptest_static_deposit_address_for_testing",
	}
	err := gripmock.AddStub("spark_internal.SparkInternalService", "create_static_deposit_utxo_swap", nil, swapSuccessStub)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "initiate_transfer", nil, nil)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round1", nil, frostRound1StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round2", nil, frostRound2StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "rollback_utxo_swap", nil, nil)
	require.NoError(t, err)

	ctx, sessionCtx := setupPgTestContext(t)
	cfg := setupTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	ownerIdentityPrivKey, ownerIdentityPub := generateFixedKeyPair(1)
	_, ownerSigningPub := generateFixedKeyPair(2)
	_, wrongSigningPub := generateFixedKeyPair(99) // Wrong verification key

	keyshare := createTestSigningKeyshare(t, ctx, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPub, ownerSigningPub)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	tree := createTestTreeForClaim(t, ctx, sessionCtx.Client)
	leaf := createTestTreeNodeAvailable(t, ctx, sessionCtx.Client, tree, keyshare)

	spendTxBytes := createValidBitcoinTxBytes(ownerIdentityPub)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(
		t, cfg, utxo, leaf,
		ownerIdentityPrivKey, ownerIdentityPub, ownerSigningPub,
		testSspSignature, spendTxBytes,
	)

	// Change verification key to wrong one
	req.SpendTxSigningJob.SigningPublicKey = wrongSigningPub

	_, err = handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "deposit address owner signing pubkey does not match the signing public key")
}
