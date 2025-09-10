package handler

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/distributed-lab/gripmock"
	eciesgo "github.com/ecies/go/v2"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

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

var testTransferID = uuid.Must(uuid.Parse("550e8400-e29b-41d4-a716-446655440000"))

func createOldBitcoinTxBytes(t *testing.T, receiverPubKey keys.Public) []byte {
	p2trScript, err := common.P2TRScriptFromPubKey(receiverPubKey)
	require.NoError(t, err)

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
	userPrivateKey keys.Private,
) []byte {
	hash := CreateUserStatement(hex.EncodeToString(txid), vout, network, requestType, totalAmount, sspSignature)
	return ecdsa.Sign(userPrivateKey.ToBTCEC(), hash).Serialize()
}

func createTestStaticDepositAddress(t *testing.T, ctx context.Context, client *ent.Client, keyshare *ent.SigningKeyshare, ownerIdentityPubKey, ownerSigningPubKey keys.Public) *ent.DepositAddress {
	depositAddress, err := client.DepositAddress.Create().
		SetAddress("bc1ptest_static_deposit_address_for_testing").
		SetOwnerIdentityPubkey(ownerIdentityPubKey).
		SetOwnerSigningPubkey(ownerSigningPubKey).
		SetSigningKeyshare(keyshare).
		SetIsStatic(true).
		Save(ctx)
	require.NoError(t, err)
	return depositAddress
}

func createTestUtxo(t *testing.T, ctx context.Context, client *ent.Client, depositAddress *ent.DepositAddress, blockHeight int64) *ent.Utxo {
	validTxBytes := createOldBitcoinTxBytes(t, depositAddress.OwnerIdentityPubkey)
	txid := validTxBytes[:32] // Mock txid from tx bytes

	testUtxo, err := client.Utxo.Create().
		SetNetwork(st.NetworkRegtest).
		SetTxid(txid).
		SetVout(0).
		SetBlockHeight(blockHeight).
		SetAmount(10000).
		SetPkScript([]byte("test_pk_script")).
		SetDepositAddress(depositAddress).
		Save(ctx)
	require.NoError(t, err)
	return testUtxo
}

func createTestUtxoSwap(t *testing.T, ctx context.Context, rng io.Reader, client *ent.Client, utxo *ent.Utxo, status st.UtxoSwapStatus) *ent.UtxoSwap {
	userPubKey := keys.MustGeneratePrivateKeyFromRand(rng).Public()
	coordinatorPubKey := keys.MustGeneratePrivateKeyFromRand(rng).Public()

	utxoSwap, err := client.UtxoSwap.Create().
		SetStatus(status).
		SetUtxo(utxo).
		SetRequestType(st.UtxoSwapRequestTypeRefund).
		SetCreditAmountSats(10000).
		SetSspSignature([]byte("test_ssp_signature")).
		SetSspIdentityPublicKey(userPubKey.Serialize()).
		SetUserIdentityPublicKey(userPubKey.Serialize()).
		SetCoordinatorIdentityPublicKey(coordinatorPubKey.Serialize()).
		Save(ctx)
	require.NoError(t, err)
	return utxoSwap
}

func createTestBlockHeight(t *testing.T, ctx context.Context, client *ent.Client, height int64) {
	_, err := client.BlockHeight.Create().SetNetwork(st.NetworkRegtest).SetHeight(height).Save(ctx)
	require.NoError(t, err)
}

func setUpTestConfigWithRegtestNoAuthz(t *testing.T) *so.Config {
	cfg, err := testutil.TestConfig()
	require.NoError(t, err)

	// Add regtest support and disable authz for tests
	cfg.SupportedNetworks = []common.Network{common.Regtest}
	cfg.BitcoindConfigs = map[string]so.BitcoindConfig{
		"regtest": {DepositConfirmationThreshold: 1},
	}
	return cfg
}

func createValidSecretShares(cfg *so.Config, rng io.Reader) (*pb.SecretShare, map[string][]byte) {
	sharePrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	sharePubKey := sharePrivKey.Public()

	secretShare := &pb.SecretShare{
		SecretShare: sharePrivKey.Serialize(),
		Proofs:      [][]byte{sharePubKey.Serialize()},
	}

	pubkeySharesTweak := make(map[string][]byte)
	for identifier := range cfg.SigningOperatorMap {
		privKey := keys.MustGeneratePrivateKeyFromRand(rng)
		pubkeySharesTweak[identifier] = privKey.Public().Serialize()
	}

	return secretShare, pubkeySharesTweak
}

func createTestTreeNodeAvailable(
	t *testing.T,
	ctx context.Context,
	client *ent.Client,
	tree *ent.Tree,
	keyshare *ent.SigningKeyshare,
	ownerIdentityPubKey, ownerSigningPubKey, verifyingPubKey keys.Public,
) *ent.TreeNode {
	validTx := createOldBitcoinTxBytes(t, ownerIdentityPubKey)
	leaf, err := client.TreeNode.Create().
		SetStatus(st.TreeNodeStatusAvailable).
		SetTree(tree).
		SetSigningKeyshare(keyshare).
		SetValue(1000).
		SetVerifyingPubkey(verifyingPubKey.Serialize()).
		SetOwnerIdentityPubkey(ownerIdentityPubKey.Serialize()).
		SetOwnerSigningPubkey(ownerSigningPubKey.Serialize()).
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

func createTestTreeNodeForStaticDeposit(
	t *testing.T,
	ctx context.Context,
	rng io.Reader,
	client *ent.Client,
	tree *ent.Tree,
	keyshare *ent.SigningKeyshare,
	ownerIdentityPubKey, ownerSigningPubKey keys.Public,
) *ent.TreeNode {
	verifyingPubKey := keys.MustGeneratePrivateKeyFromRand(rng).Public()

	validTx := createOldBitcoinTxBytes(t, ownerIdentityPubKey)

	leaf, err := client.TreeNode.Create().
		SetStatus(st.TreeNodeStatusAvailable).
		SetTree(tree).
		SetSigningKeyshare(keyshare).
		SetValue(1000).
		SetVerifyingPubkey(verifyingPubKey.Serialize()).
		SetOwnerIdentityPubkey(ownerIdentityPubKey.Serialize()).
		SetOwnerSigningPubkey(ownerSigningPubKey.Serialize()).
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

func createMockKeyTweakPackage(t *testing.T, cfg *so.Config, rng io.Reader, leafID uuid.UUID, ownerIdentityPrivKey keys.Private, transferID uuid.UUID) (map[string][]byte, []byte) {
	secretShare, pubkeySharesTweak := createValidSecretShares(cfg, rng)
	publicKey, err := eciesgo.NewPublicKeyFromBytes(cfg.IdentityPublicKey().Serialize())
	require.NoError(t, err)

	secretCipher, err := eciesgo.Encrypt(publicKey, secretShare.GetSecretShare())
	require.NoError(t, err)

	leafTweak := &pb.SendLeafKeyTweak{
		LeafId:            leafID.String(),
		SecretShareTweak:  secretShare,
		PubkeySharesTweak: pubkeySharesTweak,
		SecretCipher:      secretCipher,
		Signature:         []byte("mock_signature_data_for_testing_use_in_tests"),
	}

	leafTweaks := &pb.SendLeafKeyTweaks{
		LeavesToSend: []*pb.SendLeafKeyTweak{leafTweak},
	}

	leafTweaksData, err := proto.Marshal(leafTweaks)
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

	payloadToSign := common.GetTransferPackageSigningPayload(transferID, tempTransferPackage)
	signature := ecdsa.Sign(ownerIdentityPrivKey.ToBTCEC(), payloadToSign)
	transferPackageUserSignature := signature.Serialize()

	return keyTweakPackage, transferPackageUserSignature
}

func createUserSignedTxSigningJob(rng io.Reader, leafID uuid.UUID, rawTx []byte, soIdentifier string) *pb.UserSignedTxSigningJob {
	return &pb.UserSignedTxSigningJob{
		LeafId: leafID.String(),
		SigningCommitments: &pb.SigningCommitments{
			SigningCommitments: map[string]*pbcommon.SigningCommitment{
				soIdentifier: {
					Hiding:  keys.MustGeneratePrivateKeyFromRand(rng).Public().Serialize(),
					Binding: keys.MustGeneratePrivateKeyFromRand(rng).Public().Serialize(),
				},
			},
		},
		SigningNonceCommitment: &pbcommon.SigningCommitment{
			Hiding:  keys.MustGeneratePrivateKeyFromRand(rng).Public().Serialize(),
			Binding: keys.MustGeneratePrivateKeyFromRand(rng).Public().Serialize(),
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
	rng io.Reader,
	ownerIdentityPrivKey keys.Private,
	ownerSigningPubKey keys.Public,
	testSspSignature, spendTxBytes []byte,
) *pbssp.InitiateStaticDepositUtxoSwapRequest {
	testTotalAmount := uint64(1000)
	userSignature := createValidUserSignatureForTest(
		utxo.Txid,
		utxo.Vout,
		common.Regtest,
		pb.UtxoSwapRequestType_Fixed,
		testTotalAmount,
		testSspSignature,
		ownerIdentityPrivKey,
	)

	keyTweakPackage, transferPackageUserSignature := createMockKeyTweakPackage(t, cfg, rng, leaf.ID, ownerIdentityPrivKey, testTransferID)
	ownerIdentityPubKey := ownerIdentityPrivKey.Public()

	return &pbssp.InitiateStaticDepositUtxoSwapRequest{
		OnChainUtxo: &pb.UTXO{
			Txid:    utxo.Txid,
			Vout:    utxo.Vout,
			Network: pb.Network_REGTEST,
		},
		SspSignature:  testSspSignature,
		UserSignature: userSignature,
		Transfer: &pb.StartTransferRequest{
			TransferId:                testTransferID.String(),
			OwnerIdentityPublicKey:    ownerIdentityPubKey.Serialize(),
			ReceiverIdentityPublicKey: ownerIdentityPubKey.Serialize(),
			ExpiryTime:                timestamppb.New(time.Now().Add(24 * time.Hour)),
			TransferPackage: &pb.TransferPackage{
				LeavesToSend: []*pb.UserSignedTxSigningJob{
					createUserSignedTxSigningJob(rng, leaf.ID, createValidBitcoinTxBytes(t, ownerIdentityPubKey), cfg.Identifier),
				},
				KeyTweakPackage: keyTweakPackage,
				UserSignature:   transferPackageUserSignature,
			},
		},
		SpendTxSigningJob: &pb.SigningJob{
			SigningPublicKey:       ownerSigningPubKey.Serialize(),
			RawTx:                  spendTxBytes,
			SigningNonceCommitment: createTestSigningCommitment(rng),
		},
	}
}

func TestCreateStaticDepositUtxoRefundWithRollback_OneUnsuccessfulCreate(t *testing.T) {
	testutil.RequireGripMock(t)
	defer func() { _ = gripmock.Clear() }()

	// Get all active server ports
	ports := gripmock.GetActivePorts()
	require.NotEmpty(t, ports, "Expected at least one gripmock server to be running")

	// Set up failure stub on first server only
	failureStub := map[string]any{"error": "Failed to create utxo swap"}
	err := gripmock.AddStubToPort(ports[0], "spark_internal.SparkInternalService", "create_static_deposit_utxo_refund", nil, failureStub)
	require.NoError(t, err)

	// Set up success stubs on all other servers
	successStub := map[string]any{
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

	ctx, sessionCtx := db.ConnectToTestPostgres(t)
	cfg := setUpTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	rng := rand.NewChaCha8([32]byte{})
	ownerIdentityPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	ownerIdentityPubKey := ownerIdentityPrivKey.Public()
	ownerSigningPubKey := keys.MustGeneratePrivateKeyFromRand(rng).Public()

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)
	keyshare := createTestSigningKeyshare(t, ctx, rng, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPubKey, ownerSigningPubKey)
	testUtxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	refundTxBytes := createValidBitcoinTxBytes(t, ownerIdentityPubKey)
	spendTxSighash := refundTxBytes[:32]

	userSignature := createValidUserSignatureForTest(
		testUtxo.Txid,
		testUtxo.Vout,
		common.Regtest,
		pb.UtxoSwapRequestType_Refund,
		10000,
		spendTxSighash,
		ownerIdentityPrivKey,
	)

	req := &pb.InitiateStaticDepositUtxoRefundRequest{
		OnChainUtxo: &pb.UTXO{
			Txid:    testUtxo.Txid,
			Vout:    testUtxo.Vout,
			Network: pb.Network_REGTEST,
		},
		RefundTxSigningJob: &pb.SigningJob{
			SigningPublicKey:       ownerSigningPubKey.Serialize(),
			RawTx:                  refundTxBytes,
			SigningNonceCommitment: createTestSigningCommitment(rng),
		},
		UserSignature: userSignature,
	}

	err = handler.createStaticDepositUtxoRefundWithRollback(ctx, cfg, req)
	require.Error(t, err) // Expect this to fail, since it's invalid

	// Commit tx to persist rollback changes
	tx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())

	// Verify rollback worked - no active UtxoSwap should exist for this UTXO
	activeSwapExists, err := sessionCtx.Client.UtxoSwap.Query().
		Where(
			utxoswap.HasUtxoWith(utxo.IDEQ(testUtxo.ID)),
			utxoswap.StatusNEQ(st.UtxoSwapStatusCancelled),
		).
		Exist(ctx)
	require.NoError(t, err)
	assert.False(t, activeSwapExists, "No active UtxoSwap should exist")
}

func TestCreateStaticDepositUtxoRefundWithRollback_RollbackMarksUtxoSwapAsCancelled(t *testing.T) {
	testutil.RequireGripMock(t)
	err := gripmock.AddStub("spark_internal.SparkInternalService", "rollback_utxo_swap", nil, nil)
	require.NoError(t, err)

	ctx, sessionCtx := db.ConnectToTestPostgres(t)
	cfg := setUpTestConfigWithRegtestNoAuthz(t)

	rng := rand.NewChaCha8([32]byte{})
	ownerIdentityPubKey := keys.MustGeneratePrivateKeyFromRand(rng).Public()
	ownerSigningPubKey := keys.MustGeneratePrivateKeyFromRand(rng).Public()

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)
	keyshare := createTestSigningKeyshare(t, ctx, rng, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPubKey, ownerSigningPubKey)
	utxoEntity := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	utxoSwap, err := sessionCtx.Client.UtxoSwap.Create().
		SetStatus(st.UtxoSwapStatusCreated).
		SetRequestType(st.UtxoSwapRequestTypeRefund).
		SetUserIdentityPublicKey(ownerIdentityPubKey.Serialize()).
		SetCoordinatorIdentityPublicKey(cfg.IdentityPublicKey().Serialize()).
		SetUtxo(utxoEntity).
		Save(ctx)
	require.NoError(t, err)

	internalHandler := NewInternalDepositHandler(cfg)
	rollbackRequest, err := GenerateRollbackStaticDepositUtxoSwapForUtxoRequest(ctx, cfg, &pb.UTXO{
		Txid:    utxoEntity.Txid,
		Vout:    utxoEntity.Vout,
		Network: pb.Network_REGTEST,
	})
	require.NoError(t, err)

	_, err = internalHandler.RollbackUtxoSwap(ctx, cfg, rollbackRequest)
	require.NoError(t, err)

	// Commit tx before checking the result
	tx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())

	// check result in separate context
	updatedUtxoSwap, err := sessionCtx.Client.UtxoSwap.Get(t.Context(), utxoSwap.ID)
	require.NoError(t, err)
	assert.Equal(t, st.UtxoSwapStatusCancelled, updatedUtxoSwap.Status)
}

func TestInitiateStaticDepositUtxoSwap_InvalidUserSignature(t *testing.T) {
	testutil.RequireGripMock(t)
	defer func() { _ = gripmock.Clear() }()

	rng := rand.NewChaCha8([32]byte{})
	ownerIdentityPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	ownerIdentityPubKey := ownerIdentityPrivKey.Public()
	ownerSigningPubKey := keys.MustGeneratePrivateKeyFromRand(rng).Public()
	wrongPrivKey := keys.MustGeneratePrivateKeyFromRand(rng) // Wrong private key for creating invalid signature

	ctx, sessionCtx := db.ConnectToTestPostgres(t)
	cfg := setUpTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)
	keyshare := createTestSigningKeyshare(t, ctx, rng, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, wrongPrivKey.Public(), ownerSigningPubKey)
	testUtxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	// Add all necessary gripmock stubs to reach signature validation
	err := gripmock.AddStub("spark_internal.SparkInternalService", "frost_round1", nil, frostRound1StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round2", nil, frostRound2StubOutput)
	require.NoError(t, err)
	swapSuccessStub := map[string]any{
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

	spendTxBytes := createValidBitcoinTxBytes(t, ownerIdentityPubKey)
	spendTxSigHash, _, err := GetTxSigningInfo(ctx, testUtxo, spendTxBytes)
	require.NoError(t, err)

	aggregateFrostStubOutput := map[string]any{
		"signature": createValidTaprootSignature(t, ownerIdentityPrivKey, spendTxSigHash),
	}
	err = gripmock.AddStub("frost.FrostService", "aggregate_frost", nil, aggregateFrostStubOutput)
	require.NoError(t, err)

	tree := createTestTreeForClaim(t, ctx, ownerIdentityPubKey, sessionCtx.Client)
	leaf := createTestTreeNodeForStaticDeposit(t, ctx, rng, sessionCtx.Client, tree, keyshare, ownerIdentityPubKey, ownerSigningPubKey)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	// Create request with wrong pk to generate invalid signature
	req := createMockStaticDepositUtxoSwapRequest(t, cfg, testUtxo, leaf, rng, wrongPrivKey, ownerSigningPubKey, testSspSignature, spendTxBytes)
	req.Transfer.OwnerIdentityPublicKey = ownerIdentityPubKey.Serialize()

	_, err = handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	require.ErrorContains(t, err, "invalid signature")
}
