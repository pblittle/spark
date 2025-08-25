//go:build gripmock
// +build gripmock

package handler

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	eciesgo "github.com/ecies/go/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/distributed-lab/gripmock"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/keys"
	pbcommon "github.com/lightsparkdev/spark/proto/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/utxo"
	"github.com/lightsparkdev/spark/so/ent/utxoswap"
	testutil "github.com/lightsparkdev/spark/testing"
)

func testTransferID() string {
	return "550e8400-e29b-41d4-a716-446655440000"
}

func createOldBitcoinTxBytes(receiverPubKey []byte) []byte {
	pubkey, err := secp256k1.ParsePubKey(receiverPubKey)
	if err != nil {
		panic(err)
	}

	p2trScript, err := common.P2TRScriptFromPubKey(keys.PublicKeyFromKey(*pubkey))
	if err != nil {
		panic(err)
	}

	// sequence = 10275 = 0x2823 (little-endian: 23 28 00 00)
	scriptLen := fmt.Sprintf("%02x", len(p2trScript))
	hexStr := "01010101010000000000000000000000000000000000000000000000000000000000000000ffffffff002328000001e803000000000000" +
		scriptLen +
		hex.EncodeToString(p2trScript) +
		"000000000000000000000000000000000000000000"
	bytes, _ := hex.DecodeString(hexStr)
	return bytes
}

func createValidUserSignatureForTest(
	txid []byte,
	vout uint32,
	network common.Network,
	requestType pb.UtxoSwapRequestType,
	totalAmount uint64,
	sspSignature []byte,
	userPrivateKey *secp256k1.PrivateKey,
) ([]byte, error) {
	messageHash, err := CreateUserStatement(
		hex.EncodeToString(txid),
		vout,
		network,
		requestType,
		totalAmount,
		sspSignature,
	)
	if err != nil {
		return nil, err
	}

	signature := ecdsa.Sign(userPrivateKey, messageHash)
	return signature.Serialize(), nil
}

func createTestStaticDepositAddress(t *testing.T, ctx context.Context, client *ent.Client, keyshare *ent.SigningKeyshare, ownerIdentityPub, ownerSigningPub []byte) *ent.DepositAddress {
	depositAddress, err := client.DepositAddress.Create().
		SetAddress("bc1ptest_static_deposit_address_for_testing").
		SetOwnerIdentityPubkey(ownerIdentityPub).
		SetOwnerSigningPubkey(ownerSigningPub).
		SetSigningKeyshare(keyshare).
		SetIsStatic(true).
		Save(ctx)
	require.NoError(t, err)
	return depositAddress
}

func createTestUtxo(t *testing.T, ctx context.Context, client *ent.Client, depositAddress *ent.DepositAddress, blockHeight int64) *ent.Utxo {
	validTxBytes := createOldBitcoinTxBytes(depositAddress.OwnerIdentityPubkey)
	txid := validTxBytes[:32] // Mock txid from tx bytes

	utxo, err := client.Utxo.Create().
		SetNetwork(st.NetworkRegtest).
		SetTxid(txid).
		SetVout(0).
		SetBlockHeight(blockHeight).
		SetAmount(10000).
		SetPkScript([]byte("test_pk_script")).
		SetDepositAddress(depositAddress).
		Save(ctx)
	require.NoError(t, err)
	return utxo
}

func createTestUtxoSwap(t *testing.T, ctx context.Context, client *ent.Client, utxo *ent.Utxo, status st.UtxoSwapStatus) *ent.UtxoSwap {
	_, userPub := generateFixedKeyPair(1)
	_, coordinatorPub := generateFixedKeyPair(6)

	utxoSwap, err := client.UtxoSwap.Create().
		SetStatus(status).
		SetUtxo(utxo).
		SetRequestType(st.UtxoSwapRequestTypeRefund).
		SetCreditAmountSats(10000).
		SetSspSignature([]byte("test_ssp_signature")).
		SetSspIdentityPublicKey(userPub).
		SetUserIdentityPublicKey(userPub).
		SetCoordinatorIdentityPublicKey(coordinatorPub).
		Save(ctx)
	require.NoError(t, err)
	return utxoSwap
}

func createTestBlockHeight(t *testing.T, ctx context.Context, client *ent.Client, height int64) {
	_, err := client.BlockHeight.Create().
		SetNetwork(st.NetworkRegtest).
		SetHeight(height).
		Save(ctx)
	require.NoError(t, err)
}

func setupTestConfigWithRegtestNoAuthz(t *testing.T) *so.Config {
	cfg, err := testutil.TestConfig()
	require.NoError(t, err)

	// Add regtest support and disable authz for tests
	cfg.SupportedNetworks = []common.Network{common.Regtest}
	cfg.BitcoindConfigs = map[string]so.BitcoindConfig{
		"regtest": {
			DepositConfirmationThreshold: 1,
		},
	}

	return cfg
}

func createValidSecretShares(cfg *so.Config) (*pb.SecretShare, map[string][]byte) {
	sharePrivKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}

	sharePubKey := sharePrivKey.PubKey()

	secretShare := &pb.SecretShare{
		SecretShare: sharePrivKey.Serialize(),
		Proofs:      [][]byte{sharePubKey.SerializeCompressed()},
	}

	pubkeySharesTweak := make(map[string][]byte)
	i := 201
	for identifier := range cfg.SigningOperatorMap {
		_, pubKey := generateFixedKeyPair(byte(i))
		pubkeySharesTweak[identifier] = pubKey
		i++
	}

	return secretShare, pubkeySharesTweak
}

func createValidECDSASignature(privateKey *secp256k1.PrivateKey, messageHash []byte) []byte {
	signature := ecdsa.Sign(privateKey, messageHash)
	return signature.Serialize() // DER format
}

func createTestLeafRefundTxSigningJobForStatic(leaf *ent.TreeNode) *pb.LeafRefundTxSigningJob {
	validTxBytes := createValidBitcoinTxBytes(leaf.OwnerIdentityPubkey)

	return &pb.LeafRefundTxSigningJob{
		LeafId: leaf.ID.String(),
		RefundTxSigningJob: &pb.SigningJob{
			SigningPublicKey:       make33ByteKey("test_signing_pubkey_33_bytes"),
			RawTx:                  validTxBytes,
			SigningNonceCommitment: createTestSigningCommitment(),
		},
		DirectRefundTxSigningJob: &pb.SigningJob{
			SigningPublicKey:       make33ByteKey("test_direct_signing_33_bytes"),
			RawTx:                  validTxBytes,
			SigningNonceCommitment: createTestSigningCommitment(),
		},
		DirectFromCpfpRefundTxSigningJob: &pb.SigningJob{
			SigningPublicKey:       make33ByteKey("test_direct_cpfp_signing_33"),
			RawTx:                  validTxBytes,
			SigningNonceCommitment: createTestSigningCommitment(),
		},
	}
}

func createTestTreeNodeAvailable(t *testing.T, ctx context.Context, client *ent.Client, tree *ent.Tree, keyshare *ent.SigningKeyshare) *ent.TreeNode {
	_, verifyingPub := generateFixedKeyPair(5)
	_, ownerPub := generateFixedKeyPair(1)
	_, ownerSigningPub := generateFixedKeyPair(2)

	validTx := createOldBitcoinTxBytes(ownerPub)

	leaf, err := client.TreeNode.Create().
		SetStatus(st.TreeNodeStatusAvailable).
		SetTree(tree).
		SetSigningKeyshare(keyshare).
		SetValue(1000).
		SetVerifyingPubkey(verifyingPub).
		SetOwnerIdentityPubkey(ownerPub).
		SetOwnerSigningPubkey(ownerSigningPub).
		SetRawTx(validTx).
		SetRawRefundTx(validTx).
		SetDirectTx(validTx).
		SetDirectRefundTx(validTx).
		SetDirectFromCpfpRefundTx(validTx).
		SetVout(0).
		Save(ctx)
	require.NoError(t, err)
	return leaf
}

func createTestTreeNodeForStaticDeposit(t *testing.T, ctx context.Context, client *ent.Client, tree *ent.Tree, keyshare *ent.SigningKeyshare, ownerIdentityPub []byte) *ent.TreeNode {
	_, verifyingPub := generateFixedKeyPair(5)
	_, ownerSigningPub := generateFixedKeyPair(6)

	validTx := createOldBitcoinTxBytes(ownerIdentityPub)

	leaf, err := client.TreeNode.Create().
		SetStatus(st.TreeNodeStatusAvailable).
		SetTree(tree).
		SetSigningKeyshare(keyshare).
		SetValue(1000).
		SetVerifyingPubkey(verifyingPub).
		SetOwnerIdentityPubkey(ownerIdentityPub).
		SetOwnerSigningPubkey(ownerSigningPub).
		SetRawTx(validTx).
		SetRawRefundTx(validTx).
		SetDirectTx(validTx).
		SetDirectRefundTx(validTx).
		SetDirectFromCpfpRefundTx(validTx).
		SetVout(0).
		Save(ctx)
	require.NoError(t, err)
	return leaf
}

func createMockKeyTweakPackage(t *testing.T, cfg *so.Config, leafID string, ownerIdentityPrivKey []byte, transferID string) (map[string][]byte, []byte) {
	secretShare, pubkeySharesTweak := createValidSecretShares(cfg)

	leafTweak := &pb.SendLeafKeyTweak{
		LeafId:            leafID,
		SecretShareTweak:  secretShare,
		PubkeySharesTweak: pubkeySharesTweak,
		SecretCipher:      make32ByteKey("mock_secret_cipher"),
		Signature:         []byte("mock_signature_data_for_testing_use_in_tests"),
	}

	leafTweaks := &pb.SendLeafKeyTweaks{
		LeavesToSend: []*pb.SendLeafKeyTweak{leafTweak},
	}

	leafTweaksData, err := proto.Marshal(leafTweaks)
	require.NoError(t, err)

	publicKey, err := eciesgo.NewPublicKeyFromBytes(cfg.IdentityPublicKey().Serialize())
	require.NoError(t, err)
	encryptedData, err := eciesgo.Encrypt(publicKey, leafTweaksData)
	require.NoError(t, err)

	keyTweakPackage := map[string][]byte{
		cfg.Identifier: encryptedData,
	}

	tempTransferPackage := &pb.TransferPackage{
		LeavesToSend:    []*pb.UserSignedTxSigningJob{},
		KeyTweakPackage: keyTweakPackage,
		UserSignature:   nil,
	}

	transferUUID, err := uuid.Parse(transferID)
	require.NoError(t, err)

	payloadToSign := common.GetTransferPackageSigningPayload(transferUUID, tempTransferPackage)
	ownerPrivKey := secp256k1.PrivKeyFromBytes(ownerIdentityPrivKey)
	signature := ecdsa.Sign(ownerPrivKey, payloadToSign)
	transferPackageUserSignature := signature.Serialize()

	return keyTweakPackage, transferPackageUserSignature
}

func createUserSignedTxSigningJob(leafID string, rawTx []byte, soIdentifier string) *pb.UserSignedTxSigningJob {
	return &pb.UserSignedTxSigningJob{
		LeafId: leafID,
		SigningCommitments: &pb.SigningCommitments{
			SigningCommitments: map[string]*pbcommon.SigningCommitment{
				soIdentifier: {
					Hiding:  make33ByteKey("test_hiding"),
					Binding: make33ByteKey("test_binding"),
				},
			},
		},
		SigningNonceCommitment: &pbcommon.SigningCommitment{
			Hiding:  make33ByteKey("test_nonce_hiding"),
			Binding: make33ByteKey("test_nonce_binding"),
		},
		UserSignature: []byte("test_user_signature_for_refund_tx"),
		RawTx:         rawTx,
	}
}

func createMockStaticDepositUtxoSwapRequest(
	t *testing.T,
	cfg *so.Config,
	utxo *ent.Utxo,
	leaf *ent.TreeNode,
	ownerIdentityPrivKey, ownerIdentityPub, ownerSigningPub []byte,
	testSspSignature []byte,
	spendTxBytes []byte,
) *pbssp.InitiateStaticDepositUtxoSwapRequest {

	testTotalAmount := uint64(1000)
	transferID := testTransferID()

	ownerIdentityPrivKeySecp := secp256k1.PrivKeyFromBytes(ownerIdentityPrivKey)
	userSignature, err := createValidUserSignatureForTest(
		utxo.Txid,
		uint32(utxo.Vout),
		common.Regtest,
		pb.UtxoSwapRequestType_Fixed,
		testTotalAmount,
		testSspSignature,
		ownerIdentityPrivKeySecp,
	)
	require.NoError(t, err)

	keyTweakPackage, transferPackageUserSignature := createMockKeyTweakPackage(
		t, cfg, leaf.ID.String(), ownerIdentityPrivKey, transferID,
	)

	return &pbssp.InitiateStaticDepositUtxoSwapRequest{
		OnChainUtxo: &pb.UTXO{
			Txid:    utxo.Txid,
			Vout:    uint32(utxo.Vout),
			Network: pb.Network_REGTEST,
		},
		SspSignature:  testSspSignature,
		UserSignature: userSignature,
		Transfer: &pb.StartTransferRequest{
			TransferId:                transferID,
			OwnerIdentityPublicKey:    ownerIdentityPub,
			ReceiverIdentityPublicKey: ownerIdentityPub,
			ExpiryTime:                timestamppb.New(time.Now().Add(24 * time.Hour)),
			TransferPackage: &pb.TransferPackage{
				LeavesToSend: []*pb.UserSignedTxSigningJob{
					createUserSignedTxSigningJob(leaf.ID.String(), createValidBitcoinTxBytes(ownerIdentityPub), cfg.Identifier),
				},
				KeyTweakPackage: keyTweakPackage,
				UserSignature:   transferPackageUserSignature,
			},
		},
		SpendTxSigningJob: &pb.SigningJob{
			SigningPublicKey:       ownerSigningPub,
			RawTx:                  spendTxBytes,
			SigningNonceCommitment: createTestSigningCommitment(),
		},
	}
}

func TestCreateStaticDepositUtxoRefundWithRollback_OneUnsuccessfulCreate(t *testing.T) {
	defer func() {
		_ = gripmock.Clear()
	}()

	// Get all active server ports
	ports := gripmock.GetActivePorts()
	require.NotEmpty(t, ports, "Expected at least one gripmock server to be running")

	// Setup failure stub on first server only
	failureStub := map[string]interface{}{
		"error": "Failed to create utxo swap",
	}
	err := gripmock.AddStubToPort(ports[0], "spark_internal.SparkInternalService", "create_static_deposit_utxo_refund", nil, failureStub)
	require.NoError(t, err)

	// Setup success stubs on all other servers
	successStub := map[string]interface{}{
		"UtxoDepositAddress": "bc1ptest_static_deposit_address_for_testing",
	}
	for _, port := range ports[1:] {
		err = gripmock.AddStubToPort(port, "spark_internal.SparkInternalService", "create_static_deposit_utxo_refund", nil, successStub)
		require.NoError(t, err)
	}

	err = gripmock.AddStub("spark_internal.SparkInternalService", "rollback_utxo_swap", nil, nil)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round1", nil, frostRound1StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round2", nil, frostRound2StubOutput)
	require.NoError(t, err)

	ctx, sessionCtx := setupPgTestContext(t)

	cfg := setupTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	// Generate consistent keys
	ownerIdentityPrivKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	ownerIdentityPub := ownerIdentityPrivKey.PubKey().SerializeCompressed()

	ownerSigningPrivKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	ownerSigningPub := ownerSigningPrivKey.PubKey().SerializeCompressed()

	keyshare := createTestSigningKeyshare(t, ctx, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPub, ownerSigningPub)
	testUtxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	refundTxBytes := createValidBitcoinTxBytes(ownerIdentityPub)
	spendTxSighash := refundTxBytes[:32]

	userSignature, err := createValidUserSignatureForTest(
		testUtxo.Txid,
		uint32(testUtxo.Vout),
		common.Regtest,
		pb.UtxoSwapRequestType_Refund,
		10000,
		spendTxSighash,
		ownerIdentityPrivKey,
	)
	require.NoError(t, err)

	req := &pb.InitiateStaticDepositUtxoRefundRequest{
		OnChainUtxo: &pb.UTXO{
			Txid:    testUtxo.Txid,
			Vout:    uint32(testUtxo.Vout),
			Network: pb.Network_REGTEST,
		},
		RefundTxSigningJob: &pb.SigningJob{
			SigningPublicKey:       ownerSigningPub,
			RawTx:                  refundTxBytes,
			SigningNonceCommitment: createTestSigningCommitment(),
		},
		UserSignature: userSignature,
	}

	err = handler.createStaticDepositUtxoRefundWithRollback(ctx, cfg, req)
	assert.Error(t, err)

	// Commit tx to persist rollback changes
	tx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)
	err = tx.Commit()
	require.NoError(t, err)

	// Verify rollback worked - no active UtxoSwap should exist for this UTXO
	activeSwapExists, err := sessionCtx.Client.UtxoSwap.Query().
		Where(utxoswap.HasUtxoWith(utxo.IDEQ(testUtxo.ID))).
		Where(utxoswap.StatusNEQ(st.UtxoSwapStatusCancelled)).
		Exist(t.Context())
	require.NoError(t, err)
	assert.False(t, activeSwapExists, "No active UtxoSwap should exist")
}

func TestCreateStaticDepositUtxoRefundWithRollback_RollbackMarksUtxoSwapAsCancelled(t *testing.T) {
	err := gripmock.AddStub("spark_internal.SparkInternalService", "rollback_utxo_swap", nil, nil)
	require.NoError(t, err)

	ctx, sessionCtx := setupPgTestContext(t)
	defer sessionCtx.Close()

	cfg := setupTestConfigWithRegtestNoAuthz(t)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	// Generate consistent keys
	ownerIdentityPrivKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	ownerIdentityPub := ownerIdentityPrivKey.PubKey().SerializeCompressed()

	ownerSigningPrivKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	ownerSigningPub := ownerSigningPrivKey.PubKey().SerializeCompressed()

	keyshare := createTestSigningKeyshare(t, ctx, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPub, ownerSigningPub)
	utxoEntity := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	utxoSwap, err := sessionCtx.Client.UtxoSwap.Create().
		SetStatus(st.UtxoSwapStatusCreated).
		SetRequestType(st.UtxoSwapRequestTypeRefund).
		SetUserIdentityPublicKey(ownerIdentityPub).
		SetCoordinatorIdentityPublicKey(cfg.IdentityPublicKey().Serialize()).
		SetUtxo(utxoEntity).
		Save(ctx)
	require.NoError(t, err)

	internalHandler := NewInternalDepositHandler(cfg)
	rollbackRequest, err := GenerateRollbackStaticDepositUtxoSwapForUtxoRequest(ctx, cfg, &pb.UTXO{
		Txid:    utxoEntity.Txid,
		Vout:    uint32(utxoEntity.Vout),
		Network: pb.Network_REGTEST,
	})
	require.NoError(t, err)

	_, err = internalHandler.RollbackUtxoSwap(ctx, cfg, rollbackRequest)
	require.NoError(t, err)

	// Commit tx before checking the result
	tx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)
	err = tx.Commit()
	require.NoError(t, err)

	// check result in separate context
	updatedUtxoSwap, err := sessionCtx.Client.UtxoSwap.Get(t.Context(), utxoSwap.ID)
	require.NoError(t, err)
	assert.Equal(t, st.UtxoSwapStatusCancelled, updatedUtxoSwap.Status)
}

func TestInitiateStaticDepositUtxoSwap_InvalidUserSignature(t *testing.T) {
	defer func() {
		_ = gripmock.Clear()
	}()

	// Add all necessary gripmock stubs to reach signature validation
	err := gripmock.AddStub("spark_internal.SparkInternalService", "frost_round1", nil, frostRound1StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round2", nil, frostRound2StubOutput)
	require.NoError(t, err)

	aggregateFrostStubOutput := map[string]interface{}{
		"signature": createValidTaprootSignature(),
	}
	err = gripmock.AddStub("frost.FrostService", "aggregate_frost", nil, aggregateFrostStubOutput)
	require.NoError(t, err)

	swapSuccessStub := map[string]interface{}{
		"UtxoDepositAddress": "bc1ptest_static_deposit_address_for_testing",
	}
	err = gripmock.AddStub("spark_internal.SparkInternalService", "create_static_deposit_utxo_swap", nil, swapSuccessStub)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "initiate_transfer", nil, nil)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "utxo_swap_completed", nil, nil)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "rollback_utxo_swap", nil, nil)
	require.NoError(t, err)

	ctx, sessionCtx := setupPgTestContext(t)

	cfg := setupTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	// Generate keys
	_, ownerIdentityPub := generateFixedKeyPair(1)
	_, ownerSigningPub := generateFixedKeyPair(2)
	wrongPrivKey, _ := generateFixedKeyPair(99) // Wrong private key for creating invalid signature

	keyshare := createTestSigningKeyshare(t, ctx, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPub, ownerSigningPub)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	tree := createTestTreeForClaim(t, ctx, sessionCtx.Client)
	leaf := createTestTreeNodeForStaticDeposit(t, ctx, sessionCtx.Client, tree, keyshare, ownerIdentityPub)

	spendTxBytes := createValidBitcoinTxBytes(ownerIdentityPub)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	// Create request with wrong pk to generate invalid signature
	req := createMockStaticDepositUtxoSwapRequest(
		t, cfg, utxo, leaf,
		wrongPrivKey, ownerIdentityPub, ownerSigningPub, // Use wrong private key
		testSspSignature, spendTxBytes,
	)

	_, err = handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature")
}
