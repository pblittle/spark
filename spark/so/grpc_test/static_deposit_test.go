package grpctest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/lightsparkdev/spark/common/keys"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbinternal "github.com/lightsparkdev/spark/proto/spark_internal"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so/db"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/utxo"
	"github.com/lightsparkdev/spark/so/ent/utxoswap"
	"github.com/lightsparkdev/spark/so/handler"
	"github.com/lightsparkdev/spark/so/objects"
	testutil "github.com/lightsparkdev/spark/test_util"
	"github.com/lightsparkdev/spark/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateUtxoIsNotSpent(t *testing.T) {
	skipIfGithubActions(t)
	bitcoinClient := testutil.GetBitcoinClient()

	// Test with faucet transaction
	coin, err := faucet.Fund()
	require.NoError(t, err)
	txidString := hex.EncodeToString(coin.OutPoint.Hash[:])
	txIDBytes, err := hex.DecodeString(txidString)
	require.NoError(t, err)
	err = handler.ValidateUtxoIsNotSpent(bitcoinClient, txIDBytes, 0)
	if err != nil {
		t.Fatalf("utxo is spent: %v, txid: %s", err, txidString)
	}

	// Spend the faucet transaction and test with a new one
	randomKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	randomAddress, err := common.P2TRRawAddressFromPublicKey(randomKey.Public(), common.Regtest)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(randomAddress)
	require.NoError(t, err)
	txOut := wire.NewTxOut(10_000, pkScript)
	unsignedDepositTx := testutil.CreateTestTransaction([]*wire.TxIn{wire.NewTxIn(coin.OutPoint, nil, [][]byte{})}, []*wire.TxOut{txOut})
	signedDepositTx, err := testutil.SignFaucetCoin(unsignedDepositTx, coin.TxOut, coin.Key)
	require.NoError(t, err)
	newTxID, err := bitcoinClient.SendRawTransaction(signedDepositTx, true)
	require.NoError(t, err)

	// Make sure the deposit tx gets enough confirmations
	randomKey, err = keys.GeneratePrivateKey()
	require.NoError(t, err)

	randomAddress, err = common.P2TRRawAddressFromPublicKey(randomKey.Public(), common.Regtest)
	require.NoError(t, err)
	_, err = bitcoinClient.GenerateToAddress(1, randomAddress, nil)
	require.NoError(t, err)

	// faucet coin is spent
	err = handler.ValidateUtxoIsNotSpent(bitcoinClient, txIDBytes, 0)
	require.Error(t, err)

	// deposit tx is not spent
	err = handler.ValidateUtxoIsNotSpent(bitcoinClient, newTxID[:], 0)
	require.NoError(t, err)
}

func TestStaticDepositSSPLegacy(t *testing.T) {
	bitcoinClient := testutil.GetBitcoinClient()

	coin, err := faucet.Fund()
	require.NoError(t, err)

	// *********************************************************************************
	// Initiate Users
	// *********************************************************************************
	// 1. Initiate Alice
	aliceConfig, err := testutil.TestWalletConfig()
	require.NoError(t, err)

	aliceLeafPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	_, err = testutil.CreateNewTree(aliceConfig, faucet, aliceLeafPrivKey, 100_000)
	require.NoError(t, err)

	aliceConn, err := common.NewGRPCConnectionWithTestTLS(aliceConfig.CoodinatorAddress(), nil)
	require.NoError(t, err)
	defer aliceConn.Close()

	aliceConnectionToken, err := wallet.AuthenticateWithConnection(context.Background(), aliceConfig, aliceConn)
	require.NoError(t, err)
	aliceCtx := wallet.ContextWithToken(context.Background(), aliceConnectionToken)

	// 2. Initiate SSP
	sspConfig, err := testutil.TestWalletConfig()
	require.NoError(t, err)

	sspLeafPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	sspRootNode, err := testutil.CreateNewTree(sspConfig, faucet, sspLeafPrivKey, 90_000)
	require.NoError(t, err)

	sspConn, err := common.NewGRPCConnectionWithTestTLS(sspConfig.CoodinatorAddress(), nil)
	require.NoError(t, err)
	defer sspConn.Close()

	sspConnectionToken, err := wallet.AuthenticateWithConnection(context.Background(), sspConfig, sspConn)
	require.NoError(t, err)
	sspCtx := wallet.ContextWithToken(context.Background(), sspConnectionToken)

	// *********************************************************************************
	// Generate a new static deposit address for Alice
	// *********************************************************************************

	// Generate a new private key for Alice. In a real Wallet that key would be derived from
	// a Signing key using derivation schema
	aliceDepositPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	leafID := uuid.New().String()

	depositResp, err := wallet.GenerateDepositAddress(
		aliceCtx,
		aliceConfig,
		aliceDepositPrivKey.Public(),
		&leafID,
		true,
	)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	// *********************************************************************************
	// Create Test Deposit TX from Alice
	// *********************************************************************************
	depositAmount := uint64(100_000)
	quoteAmount := uint64(90_000)

	randomKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	randomAddress, err := common.P2TRRawAddressFromPublicKey(randomKey.Public(), common.Regtest)
	require.NoError(t, err)

	unsignedDepositTx, err := testutil.CreateTestDepositTransactionManyOutputs(
		coin.OutPoint,
		[]string{randomAddress.String(), depositResp.DepositAddress.Address},
		int64(depositAmount),
	)
	require.NoError(t, err)
	vout := 1
	if unsignedDepositTx.TxOut[vout].Value != int64(depositAmount) {
		t.Fatalf("deposit tx output value is not equal to the deposit amount")
	}
	signedDepositTx, err := testutil.SignFaucetCoin(unsignedDepositTx, coin.TxOut, coin.Key)
	require.NoError(t, err)
	_, err = bitcoinClient.SendRawTransaction(signedDepositTx, true)
	require.NoError(t, err)

	// Make sure the deposit tx gets enough confirmations
	// Confirm extra buffer to scan more blocks than needed
	// So that we don't race the chain watcher in this test
	_, err = bitcoinClient.GenerateToAddress(6, randomAddress, nil)
	require.NoError(t, err)
	time.Sleep(10000 * time.Millisecond)

	// *********************************************************************************
	// Create request signatures
	// *********************************************************************************
	// SSP signature committing to a fixed amount quote.
	// Can be obtained from a call for a quote to SSP.
	sspSignature, err := createSspFixedQuoteSignature(
		signedDepositTx.TxHash().String(),
		uint32(vout),
		common.Regtest,
		quoteAmount,
		sspConfig.IdentityPrivateKey.ToBTCEC(),
	)
	require.NoError(t, err)

	// User signature authorizing the SSP to claim the deposit
	// in return for a transfer of a fixed amount
	userSignature, err := createUserSignature(
		signedDepositTx.TxHash().String(),
		uint32(vout),
		common.Regtest,
		pb.UtxoSwapRequestType_Fixed,
		quoteAmount,
		sspSignature,
		aliceConfig.IdentityPrivateKey.ToBTCEC(),
	)
	require.NoError(t, err)
	// *********************************************************************************
	// Create a Transfer from SSP to Alice
	// *********************************************************************************
	newLeafPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)

	transferNode := wallet.LeafKeyTweak{
		Leaf:              sspRootNode,
		SigningPrivKey:    sspLeafPrivKey,
		NewSigningPrivKey: newLeafPrivKey,
	}
	leavesToTransfer := [1]wallet.LeafKeyTweak{transferNode}

	// *********************************************************************************
	// Create spend tx from Alice's deposit to SSP L1 Wallet Address
	// *********************************************************************************
	depositOutPoint := &wire.OutPoint{Hash: signedDepositTx.TxHash(), Index: uint32(vout)}
	spendTx := wire.NewMsgTx(2)
	spendTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *depositOutPoint,
		SignatureScript:  nil,
		Witness:          nil,
		Sequence:         wire.MaxTxInSequenceNum,
	})
	spendPkScript, err := common.P2TRScriptFromPubKey(sspConfig.IdentityPrivateKey.Public())
	require.NoError(t, err)
	spendTx.AddTxOut(wire.NewTxOut(int64(quoteAmount), spendPkScript))

	// *********************************************************************************
	// Get signing commitments to use for frost signing
	// *********************************************************************************
	nodeIDs := make([]string, len(leavesToTransfer))
	for i, leaf := range leavesToTransfer {
		nodeIDs[i] = leaf.Leaf.Id
	}

	// *********************************************************************************
	// Claim Static Deposit
	// *********************************************************************************
	signedSpendTx, transfer, err := wallet.ClaimStaticDepositLegacy(
		sspCtx,
		sspConfig,
		common.Regtest,
		leavesToTransfer[:],
		spendTx,
		pb.UtxoSwapRequestType_Fixed,
		aliceDepositPrivKey,
		userSignature,
		sspSignature,
		aliceConfig.IdentityPrivateKey.Public(),
		sspConn,
		signedDepositTx.TxOut[vout],
	)
	require.NoError(t, err)

	config, err := testutil.TestConfig()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, dbCtx, err := db.NewTestContext(t, ctx, config.DatabaseDriver(), config.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer dbCtx.Close()
	schemaNetwork, err := common.SchemaNetworkFromProtoNetwork(pb.Network_REGTEST)
	require.NoError(t, err)

	depositTxID, err := hex.DecodeString(spendTx.TxIn[0].PreviousOutPoint.Hash.String())
	require.NoError(t, err)
	targetUtxo, err := dbCtx.Client.Utxo.Query().
		Where(utxo.NetworkEQ(schemaNetwork)).
		Where(utxo.Txid(depositTxID)).
		Where(utxo.Vout(depositOutPoint.Index)).
		Only(ctx)
	require.NoError(t, err)

	utxoSwap, err := dbCtx.Client.UtxoSwap.Query().Where(utxoswap.HasUtxoWith(utxo.IDEQ(targetUtxo.ID))).Only(ctx)
	require.NoError(t, err)
	assert.Equal(t, st.UtxoSwapStatusCompleted, utxoSwap.Status)
	dbTransferSspToAlice, err := utxoSwap.QueryTransfer().Only(ctx)
	require.NoError(t, err)
	assert.Equal(t, st.TransferStatusSenderKeyTweaked, dbTransferSspToAlice.Status)

	_, err = common.SerializeTx(signedSpendTx)
	require.NoError(t, err)

	// Sign, broadcast, and mine spend tx
	_, err = bitcoinClient.SendRawTransaction(signedSpendTx, true)
	require.NoError(t, err)
	assert.Equal(t, pb.TransferStatus_TRANSFER_STATUS_SENDER_KEY_TWEAKED, transfer.Status)

	// Claim transfer
	pendingTransfer, err := wallet.QueryPendingTransfers(aliceCtx, aliceConfig)
	require.NoError(t, err, "failed to query pending transfers")
	require.Len(t, pendingTransfer.Transfers, 1)
	receiverTransfer := pendingTransfer.Transfers[0]
	assert.Equal(t, pb.TransferType_UTXO_SWAP, receiverTransfer.Type)

	finalLeafPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	claimingNode := wallet.LeafKeyTweak{
		Leaf:              receiverTransfer.Leaves[0].Leaf,
		SigningPrivKey:    newLeafPrivKey,
		NewSigningPrivKey: finalLeafPrivKey,
	}
	leavesToClaim := [1]wallet.LeafKeyTweak{claimingNode}
	res, err := wallet.ClaimTransfer(aliceCtx, receiverTransfer, aliceConfig, leavesToClaim[:])
	require.NoError(t, err, "failed to ClaimTransfer")
	require.Equal(t, res[0].Id, transferNode.Leaf.Id)

	// *********************************************************************************
	// Claiming a Static Deposit again should return the same result
	// *********************************************************************************
	sparkClient := pb.NewSparkServiceClient(sspConn)
	depositTxID, err = hex.DecodeString(spendTx.TxIn[0].PreviousOutPoint.Hash.String())
	require.NoError(t, err)

	// Prepare a signing job for another spend tx, SSP should be able to make it sign by SE
	var spendTxBytes bytes.Buffer
	err = spendTx.Serialize(&spendTxBytes)
	require.NoError(t, err)
	hidingPriv, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	bindingPriv, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	hidingPubBytes := hidingPriv.Public().Serialize()
	bindingPubBytes := bindingPriv.Public().Serialize()
	spendTxNonceCommitment, err := objects.NewSigningCommitment(bindingPubBytes, hidingPubBytes)
	require.NoError(t, err)
	spendTxNonceCommitmentProto, err := spendTxNonceCommitment.MarshalProto()
	require.NoError(t, err)

	spendTxSigningJob := &pb.SigningJob{
		RawTx:                  spendTxBytes.Bytes(),
		SigningPublicKey:       aliceDepositPrivKey.Public().Serialize(),
		SigningNonceCommitment: spendTxNonceCommitmentProto,
	}

	swapResponse2, err := sparkClient.InitiateUtxoSwap(sspCtx, &pb.InitiateUtxoSwapRequest{
		OnChainUtxo: &pb.UTXO{
			Txid:    depositTxID,
			Vout:    uint32(vout),
			Network: pb.Network_REGTEST,
		},
		RequestType:   pb.UtxoSwapRequestType_Fixed,
		Amount:        &pb.InitiateUtxoSwapRequest_CreditAmountSats{CreditAmountSats: quoteAmount},
		UserSignature: userSignature,
		SspSignature:  sspSignature,
		Transfer: &pb.StartTransferRequest{
			TransferId:                transfer.Id,
			OwnerIdentityPublicKey:    sspConfig.IdentityPublicKey().Serialize(),
			ReceiverIdentityPublicKey: aliceConfig.IdentityPublicKey().Serialize(),
			ExpiryTime:                nil,
			TransferPackage:           nil,
		},
		SpendTxSigningJob: spendTxSigningJob,
	})
	require.NoError(t, err)
	require.Equal(t, transfer.Id, swapResponse2.Transfer.Id)
	require.Equal(t, pb.TransferStatus_TRANSFER_STATUS_COMPLETED, swapResponse2.Transfer.Status)
	require.Equal(t, transfer.Leaves[0].Leaf.Id, swapResponse2.Transfer.Leaves[0].Leaf.Id)

	// *********************************************************************************
	// A call to rollback should fail
	// *********************************************************************************
	sparkInternalClient := pbinternal.NewSparkInternalServiceClient(sspConn)
	rollbackUtxoSwapRequestMessageHash, err := handler.CreateUtxoSwapStatement(
		handler.UtxoSwapStatementTypeRollback,
		hex.EncodeToString(depositOutPoint.Hash[:]),
		depositOutPoint.Index,
		common.Regtest,
	)
	require.NoError(t, err)
	rollbackUtxoSwapRequestSignature := ecdsa.Sign(sspConfig.IdentityPrivateKey.ToBTCEC(), rollbackUtxoSwapRequestMessageHash)

	_, err = sparkInternalClient.RollbackUtxoSwap(sspCtx, &pbinternal.RollbackUtxoSwapRequest{
		OnChainUtxo: &pb.UTXO{
			Txid:    depositOutPoint.Hash[:],
			Vout:    depositOutPoint.Index,
			Network: pb.Network_REGTEST,
		},
		Signature:            rollbackUtxoSwapRequestSignature.Serialize(),
		CoordinatorPublicKey: aliceConfig.IdentityPublicKey().Serialize(),
	})
	require.Error(t, err)
}

func TestStaticDepositUserRefundLegacy(t *testing.T) {
	bitcoinClient := testutil.GetBitcoinClient()

	coin, err := faucet.Fund()
	require.NoError(t, err)

	// *********************************************************************************
	// Initiate Users
	// *********************************************************************************
	// 1. Initiate Alice
	aliceConfig, err := testutil.TestWalletConfig()
	require.NoError(t, err)

	aliceLeafPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	_, err = testutil.CreateNewTree(aliceConfig, faucet, aliceLeafPrivKey, 100_000)
	require.NoError(t, err)

	aliceConn, err := common.NewGRPCConnectionWithTestTLS(aliceConfig.CoodinatorAddress(), nil)
	require.NoError(t, err)
	defer aliceConn.Close()

	aliceConnectionToken, err := wallet.AuthenticateWithConnection(context.Background(), aliceConfig, aliceConn)
	require.NoError(t, err)
	aliceCtx := wallet.ContextWithToken(context.Background(), aliceConnectionToken)

	// *********************************************************************************
	// Generate a new static deposit address for Alice
	// *********************************************************************************

	// Generate a new private key for Alice. In a real Wallet that key would be derived from
	// a Signing key using derivation schema
	aliceDepositPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	leafID := uuid.New().String()

	depositResp, err := wallet.GenerateDepositAddress(
		aliceCtx,
		aliceConfig,
		aliceDepositPrivKey.Public(),
		&leafID,
		true,
	)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	// *********************************************************************************
	// Create Test Deposit TX from Alice
	// *********************************************************************************
	depositAmount := uint64(100_000)
	quoteAmount := uint64(90_000)

	randomKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	randomAddress, err := common.P2TRRawAddressFromPublicKey(randomKey.Public(), common.Regtest)
	require.NoError(t, err)

	unsignedDepositTx, err := testutil.CreateTestDepositTransactionManyOutputs(
		coin.OutPoint,
		[]string{randomAddress.String(), depositResp.DepositAddress.Address},
		int64(depositAmount),
	)
	require.NoError(t, err)
	vout := 1
	if unsignedDepositTx.TxOut[vout].Value != int64(depositAmount) {
		t.Fatalf("deposit tx output value is not equal to the deposit amount")
	}
	signedDepositTx, err := testutil.SignFaucetCoin(unsignedDepositTx, coin.TxOut, coin.Key)
	require.NoError(t, err)
	_, err = bitcoinClient.SendRawTransaction(signedDepositTx, true)
	require.NoError(t, err)

	// Make sure the deposit tx gets enough confirmations
	// Confirm extra buffer to scan more blocks than needed
	// So that we don't race the chain watcher in this test
	_, err = bitcoinClient.GenerateToAddress(6, randomAddress, nil)
	require.NoError(t, err)
	time.Sleep(10000 * time.Millisecond)

	// *********************************************************************************
	// Create spend tx from Alice's deposit to an Alice wallet address
	// *********************************************************************************
	depositOutPoint := &wire.OutPoint{Hash: signedDepositTx.TxHash(), Index: uint32(vout)}
	spendTx := wire.NewMsgTx(2)
	spendTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *depositOutPoint,
		SignatureScript:  nil,
		Witness:          nil,
		Sequence:         wire.MaxTxInSequenceNum,
	})
	spendPkScript, err := common.P2TRScriptFromPubKey(aliceConfig.IdentityPublicKey())
	require.NoError(t, err)
	spendTx.AddTxOut(wire.NewTxOut(int64(quoteAmount), spendPkScript))

	// *********************************************************************************
	// Create request signature
	// *********************************************************************************
	spendTxSighash, err := common.SigHashFromTx(
		spendTx,
		0,
		signedDepositTx.TxOut[vout],
	)
	require.NoError(t, err)
	userSignature, err := createUserSignature(
		signedDepositTx.TxHash().String(),
		uint32(vout),
		common.Regtest,
		pb.UtxoSwapRequestType_Refund,
		quoteAmount,
		spendTxSighash[:],
		aliceConfig.IdentityPrivateKey.ToBTCEC(),
	)
	require.NoError(t, err)

	// *********************************************************************************
	// Refund Static Deposit
	// *********************************************************************************
	signedSpendTx, err := wallet.RefundStaticDepositLegacy(
		aliceCtx,
		aliceConfig,
		common.Regtest,
		spendTx,
		aliceDepositPrivKey.ToBTCEC(),
		userSignature,
		aliceConfig.IdentityPublicKey().ToBTCEC(),
		signedDepositTx.TxOut[vout],
		aliceConn,
	)
	require.NoError(t, err)

	spendTxBytes, err := common.SerializeTx(signedSpendTx)
	require.NoError(t, err)
	assert.NotEmpty(t, spendTxBytes)

	// Sign, broadcast, and mine spend tx
	txid, err := bitcoinClient.SendRawTransaction(signedSpendTx, true)
	require.NoError(t, err)
	assert.Len(t, txid, 32)

	// *********************************************************************************
	// Refunding a Static Deposit again should fail
	// *********************************************************************************
	_, err = wallet.RefundStaticDepositLegacy(
		aliceCtx,
		aliceConfig,
		common.Regtest,
		spendTx,
		aliceDepositPrivKey.ToBTCEC(),
		userSignature,
		aliceConfig.IdentityPublicKey().ToBTCEC(),
		signedDepositTx.TxOut[vout],
		aliceConn,
	)
	require.Error(t, err)

	// *********************************************************************************
	// A call to rollback should fail
	// *********************************************************************************
	sparkInternalClient := pbinternal.NewSparkInternalServiceClient(aliceConn)
	rollbackUtxoSwapRequestMessageHash, err := handler.CreateUtxoSwapStatement(
		handler.UtxoSwapStatementTypeRollback,
		hex.EncodeToString(depositOutPoint.Hash[:]),
		depositOutPoint.Index,
		common.Regtest,
	)
	require.NoError(t, err)
	rollbackUtxoSwapRequestSignature := ecdsa.Sign(aliceConfig.IdentityPrivateKey.ToBTCEC(), rollbackUtxoSwapRequestMessageHash)

	_, err = sparkInternalClient.RollbackUtxoSwap(aliceCtx, &pbinternal.RollbackUtxoSwapRequest{
		OnChainUtxo: &pb.UTXO{
			Txid:    depositOutPoint.Hash[:],
			Vout:    depositOutPoint.Index,
			Network: pb.Network_REGTEST,
		},
		Signature:            rollbackUtxoSwapRequestSignature.Serialize(),
		CoordinatorPublicKey: aliceConfig.IdentityPublicKey().Serialize(),
	})
	require.Error(t, err)
}

func createUserSignature(
	transactionID string,
	outputIndex uint32,
	network common.Network,
	requestType pb.UtxoSwapRequestType,
	creditAmountSats uint64,
	sspSignature []byte,
	identityPrivateKey *secp256k1.PrivateKey,
) ([]byte, error) {
	hash, err := handler.CreateUserStatement(
		transactionID,
		outputIndex,
		network,
		requestType,
		creditAmountSats,
		sspSignature,
	)
	if err != nil {
		return nil, err
	}

	// Sign the hash of the payload using ECDSA
	signature := ecdsa.Sign(identityPrivateKey, hash)

	return signature.Serialize(), nil
}

func createSspFixedQuoteSignature(
	transactionID string,
	outputIndex uint32,
	network common.Network,
	creditAmountSats uint64,
	identityPrivateKey *secp256k1.PrivateKey,
) ([]byte, error) {
	hasher := sha256.New()

	// Writing to a sha256 never returns an error, so we don't need to check any of the errors below.
	// Add network value as UTF-8 bytes
	_, _ = hasher.Write([]byte(network.String()))

	// Add transaction ID as UTF-8 bytes
	_, _ = hasher.Write([]byte(transactionID))

	// Add output index as 4-byte unsigned integer (little-endian)
	_ = binary.Write(hasher, binary.LittleEndian, outputIndex)

	// Request type fixed amount
	_ = binary.Write(hasher, binary.LittleEndian, uint8(0))

	// Add credit amount as 8-byte unsigned integer (little-endian)
	_ = binary.Write(hasher, binary.LittleEndian, creditAmountSats)

	// Hash the payload with SHA-256
	hash := hasher.Sum(nil)

	// Sign the hash of the payload using ECDSA
	signature := ecdsa.Sign(identityPrivateKey, hash[:])

	return signature.Serialize(), nil
}

func TestStaticDepositSSP(t *testing.T) {
	bitcoinClient := testutil.GetBitcoinClient()

	coin, err := faucet.Fund()
	require.NoError(t, err)

	// *********************************************************************************
	// Initiate Users
	// *********************************************************************************
	// 1. Initiate Alice
	aliceConfig, err := testutil.TestWalletConfig()
	require.NoError(t, err)

	aliceLeafPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	_, err = testutil.CreateNewTree(aliceConfig, faucet, aliceLeafPrivKey, 100_000)
	require.NoError(t, err)

	aliceConn, err := common.NewGRPCConnectionWithTestTLS(aliceConfig.CoodinatorAddress(), nil)
	require.NoError(t, err)
	defer aliceConn.Close()

	aliceConnectionToken, err := wallet.AuthenticateWithConnection(context.Background(), aliceConfig, aliceConn)
	require.NoError(t, err)
	aliceCtx := wallet.ContextWithToken(context.Background(), aliceConnectionToken)

	// 2. Initiate SSP
	sspConfig, err := testutil.TestWalletConfig()
	require.NoError(t, err)

	sspLeafPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	sspRootNode, err := testutil.CreateNewTree(sspConfig, faucet, sspLeafPrivKey, 90_000)
	require.NoError(t, err)

	sspConn, err := common.NewGRPCConnectionWithTestTLS(sspConfig.CoodinatorAddress(), nil)
	require.NoError(t, err)
	defer sspConn.Close()

	sspConnectionToken, err := wallet.AuthenticateWithConnection(context.Background(), sspConfig, sspConn)
	require.NoError(t, err)
	sspCtx := wallet.ContextWithToken(context.Background(), sspConnectionToken)

	// *********************************************************************************
	// Generate a new static deposit address for Alice
	// *********************************************************************************

	// Generate a new private key for Alice. In a real Wallet that key would be derived from
	// a Signing key using derivation schema
	aliceDepositPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	leafID := uuid.New().String()

	depositResp, err := wallet.GenerateDepositAddress(
		aliceCtx,
		aliceConfig,
		aliceDepositPrivKey.Public(),
		&leafID,
		true,
	)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	// *********************************************************************************
	// Create Test Deposit TX from Alice
	// *********************************************************************************
	depositAmount := uint64(100_000)
	quoteAmount := uint64(90_000)

	randomKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	randomAddress, err := common.P2TRRawAddressFromPublicKey(randomKey.Public(), common.Regtest)
	require.NoError(t, err)

	unsignedDepositTx, err := testutil.CreateTestDepositTransactionManyOutputs(
		coin.OutPoint,
		[]string{randomAddress.String(), depositResp.DepositAddress.Address},
		int64(depositAmount),
	)
	require.NoError(t, err)
	vout := 1
	if unsignedDepositTx.TxOut[vout].Value != int64(depositAmount) {
		t.Fatalf("deposit tx output value is not equal to the deposit amount")
	}
	signedDepositTx, err := testutil.SignFaucetCoin(unsignedDepositTx, coin.TxOut, coin.Key)
	require.NoError(t, err)

	// *********************************************************************************
	// Create request signatures
	// *********************************************************************************
	// SSP signature committing to a fixed amount quote.
	// Can be obtained from a call for a quote to SSP.
	sspSignature, err := createSspFixedQuoteSignature(
		signedDepositTx.TxHash().String(),
		uint32(vout),
		common.Regtest,
		quoteAmount,
		sspConfig.IdentityPrivateKey.ToBTCEC(),
	)
	require.NoError(t, err)

	// User signature authorizing the SSP to claim the deposit
	// in return for a transfer of a fixed amount
	userSignature, err := createUserSignature(
		signedDepositTx.TxHash().String(),
		uint32(vout),
		common.Regtest,
		pb.UtxoSwapRequestType_Fixed,
		quoteAmount,
		sspSignature,
		aliceConfig.IdentityPrivateKey.ToBTCEC(),
	)
	require.NoError(t, err)
	// *********************************************************************************
	// Create a Transfer from SSP to Alice
	// *********************************************************************************
	newLeafPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)

	transferNode := wallet.LeafKeyTweak{
		Leaf:              sspRootNode,
		SigningPrivKey:    sspLeafPrivKey,
		NewSigningPrivKey: newLeafPrivKey,
	}
	leavesToTransfer := [1]wallet.LeafKeyTweak{transferNode}

	// *********************************************************************************
	// Create spend tx from Alice's deposit to SSP L1 Wallet Address
	// *********************************************************************************
	depositOutPoint := &wire.OutPoint{Hash: signedDepositTx.TxHash(), Index: uint32(vout)}
	spendTx := wire.NewMsgTx(2)
	spendTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *depositOutPoint,
		SignatureScript:  nil,
		Witness:          nil,
		Sequence:         wire.MaxTxInSequenceNum,
	})
	spendPkScript, err := common.P2TRScriptFromPubKey(sspConfig.IdentityPublicKey())
	require.NoError(t, err)
	spendTx.AddTxOut(wire.NewTxOut(int64(quoteAmount), spendPkScript))

	// *********************************************************************************
	// Get signing commitments to use for frost signing
	// *********************************************************************************
	nodeIDs := make([]string, len(leavesToTransfer))
	for i, leaf := range leavesToTransfer {
		nodeIDs[i] = leaf.Leaf.Id
	}

	// *********************************************************************************
	// Claim Static Deposit
	// *********************************************************************************
	// Claim when the deposit is not yet confirmed results in error
	_, _, err = wallet.ClaimStaticDeposit(
		sspCtx,
		sspConfig,
		common.Regtest,
		leavesToTransfer[:],
		spendTx,
		pb.UtxoSwapRequestType_Fixed,
		aliceDepositPrivKey.ToBTCEC(),
		userSignature,
		sspSignature,
		aliceConfig.IdentityPrivateKey.Public().ToBTCEC(),
		sspConn,
		signedDepositTx.TxOut[vout],
	)
	require.ErrorContains(t, err, "utxo not found")

	// Confirm the deposit on chain
	_, err = bitcoinClient.SendRawTransaction(signedDepositTx, true)
	require.NoError(t, err)

	// Make sure the deposit tx gets enough confirmations
	// Confirm extra buffer to scan more blocks than needed
	// So that we don't race the chain watcher in this test
	_, err = bitcoinClient.GenerateToAddress(6, randomAddress, nil)
	require.NoError(t, err)
	time.Sleep(1000 * time.Millisecond)

	// Claim when the deposit is confirmed results in success
	signedSpendTx, transfer, err := wallet.ClaimStaticDeposit(
		sspCtx,
		sspConfig,
		common.Regtest,
		leavesToTransfer[:],
		spendTx,
		pb.UtxoSwapRequestType_Fixed,
		aliceDepositPrivKey.ToBTCEC(),
		userSignature,
		sspSignature,
		aliceConfig.IdentityPublicKey().ToBTCEC(),
		sspConn,
		signedDepositTx.TxOut[vout],
	)
	require.NoError(t, err)

	config, err := testutil.TestConfig()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, dbCtx, err := db.NewTestContext(t, ctx, config.DatabaseDriver(), config.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer dbCtx.Close()

	schemaNetwork, err := common.SchemaNetworkFromProtoNetwork(pb.Network_REGTEST)
	require.NoError(t, err)

	depositTxID, err := hex.DecodeString(spendTx.TxIn[0].PreviousOutPoint.Hash.String())
	require.NoError(t, err)
	targetUtxo, err := dbCtx.Client.Utxo.Query().
		Where(utxo.NetworkEQ(schemaNetwork)).
		Where(utxo.Txid(depositTxID)).
		Where(utxo.Vout(depositOutPoint.Index)).
		Only(aliceCtx)
	require.NoError(t, err)

	utxoSwap, err := dbCtx.Client.UtxoSwap.Query().Where(utxoswap.HasUtxoWith(utxo.IDEQ(targetUtxo.ID))).Only(aliceCtx)
	require.NoError(t, err)
	assert.Equal(t, st.UtxoSwapStatusCompleted, utxoSwap.Status)
	dbTransferSspToAlice, err := utxoSwap.QueryTransfer().Only(aliceCtx)
	require.NoError(t, err)
	assert.Equal(t, st.TransferStatusSenderKeyTweaked, dbTransferSspToAlice.Status)

	_, err = common.SerializeTx(signedSpendTx)
	require.NoError(t, err)

	// Sign, broadcast, and mine spend tx
	_, err = bitcoinClient.SendRawTransaction(signedSpendTx, true)
	require.NoError(t, err)
	assert.Equal(t, pb.TransferStatus_TRANSFER_STATUS_SENDER_KEY_TWEAKED, transfer.Status)

	// Claim transfer
	pendingTransfer, err := wallet.QueryPendingTransfers(aliceCtx, aliceConfig)
	require.NoError(t, err, "failed to query pending transfers")
	assert.Len(t, pendingTransfer.Transfers, 1)
	receiverTransfer := pendingTransfer.Transfers[0]
	assert.Equal(t, pb.TransferType_UTXO_SWAP, receiverTransfer.Type)

	finalLeafPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	claimingNode := wallet.LeafKeyTweak{
		Leaf:              receiverTransfer.Leaves[0].Leaf,
		SigningPrivKey:    newLeafPrivKey,
		NewSigningPrivKey: finalLeafPrivKey,
	}
	leavesToClaim := [1]wallet.LeafKeyTweak{claimingNode}
	res, err := wallet.ClaimTransfer(
		aliceCtx,
		receiverTransfer,
		aliceConfig,
		leavesToClaim[:],
	)
	require.NoError(t, err, "failed to ClaimTransfer")
	require.Equal(t, transferNode.Leaf.Id, res[0].Id)

	// *********************************************************************************
	// Claiming a Static Deposit again should fail
	// *********************************************************************************
	sparkClient := pbssp.NewSparkSspInternalServiceClient(sspConn)
	depositTxID, err = hex.DecodeString(spendTx.TxIn[0].PreviousOutPoint.Hash.String())
	require.NoError(t, err)
	_, err = sparkClient.InitiateStaticDepositUtxoSwap(sspCtx, &pbssp.InitiateStaticDepositUtxoSwapRequest{
		OnChainUtxo: &pb.UTXO{
			Txid:    depositTxID,
			Vout:    uint32(vout),
			Network: pb.Network_REGTEST,
		},
		UserSignature: userSignature,
		SspSignature:  sspSignature,
		Transfer: &pb.StartTransferRequest{
			TransferId:                transfer.Id,
			OwnerIdentityPublicKey:    sspConfig.IdentityPublicKey().Serialize(),
			ReceiverIdentityPublicKey: aliceConfig.IdentityPublicKey().Serialize(),
			ExpiryTime:                nil,
			TransferPackage:           nil,
		},
		SpendTxSigningJob: nil,
	})

	require.ErrorContains(t, err, "utxo swap is already registered")

	// *********************************************************************************
	// A call to refund should fail
	// *********************************************************************************
	signedRefundTx, err := wallet.RefundStaticDeposit(
		aliceCtx,
		aliceConfig,
		common.Regtest,
		spendTx,
		aliceDepositPrivKey.ToBTCEC(),
		userSignature,
		aliceConfig.IdentityPrivateKey.Public().ToBTCEC(),
		signedDepositTx.TxOut[vout],
		aliceConn,
	)

	require.ErrorContains(t, err, "utxo swap is already registered")
	assert.Nil(t, signedRefundTx)
}

func TestStaticDepositUserRefund(t *testing.T) {
	bitcoinClient := testutil.GetBitcoinClient()

	coin, err := faucet.Fund()
	require.NoError(t, err)

	// *********************************************************************************
	// Initiate Users
	// *********************************************************************************
	// 1. Initiate Alice
	aliceConfig, err := testutil.TestWalletConfig()
	require.NoError(t, err)

	aliceLeafPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	_, err = testutil.CreateNewTree(aliceConfig, faucet, aliceLeafPrivKey, 100_000)
	require.NoError(t, err)

	aliceConn, err := common.NewGRPCConnectionWithTestTLS(aliceConfig.CoodinatorAddress(), nil)
	require.NoError(t, err)
	defer aliceConn.Close()

	aliceConnectionToken, err := wallet.AuthenticateWithConnection(context.Background(), aliceConfig, aliceConn)
	require.NoError(t, err)
	aliceCtx := wallet.ContextWithToken(context.Background(), aliceConnectionToken)

	// *********************************************************************************
	// Generate a new static deposit address for Alice
	// *********************************************************************************

	// Generate a new private key for Alice. In a real Wallet that key would be derived from
	// a Signing key using derivation schema
	aliceDepositPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	leafID := uuid.New().String()

	depositResp, err := wallet.GenerateDepositAddress(
		aliceCtx,
		aliceConfig,
		aliceDepositPrivKey.Public(),
		&leafID,
		true,
	)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	// *********************************************************************************
	// Create Test Deposit TX from Alice
	// *********************************************************************************
	depositAmount := uint64(100_000)
	quoteAmount := uint64(90_000)

	randomKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	randomAddress, err := common.P2TRRawAddressFromPublicKey(randomKey.Public(), common.Regtest)
	require.NoError(t, err)

	unsignedDepositTx, err := testutil.CreateTestDepositTransactionManyOutputs(
		coin.OutPoint,
		[]string{randomAddress.String(), depositResp.DepositAddress.Address},
		int64(depositAmount),
	)
	require.NoError(t, err)
	vout := 1
	if unsignedDepositTx.TxOut[vout].Value != int64(depositAmount) {
		t.Fatalf("deposit tx output value is not equal to the deposit amount")
	}
	signedDepositTx, err := testutil.SignFaucetCoin(unsignedDepositTx, coin.TxOut, coin.Key)
	require.NoError(t, err)
	_, err = bitcoinClient.SendRawTransaction(signedDepositTx, true)
	require.NoError(t, err)

	// Make sure the deposit tx gets enough confirmations
	// Confirm extra buffer to scan more blocks than needed
	// So that we don't race the chain watcher in this test
	_, err = bitcoinClient.GenerateToAddress(6, randomAddress, nil)
	require.NoError(t, err)
	time.Sleep(10000 * time.Millisecond)

	// *********************************************************************************
	// Create spend tx from Alice's deposit to an Alice wallet address
	// *********************************************************************************
	depositOutPoint := &wire.OutPoint{Hash: signedDepositTx.TxHash(), Index: uint32(vout)}
	spendTx := wire.NewMsgTx(2)
	spendTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *depositOutPoint,
		SignatureScript:  nil,
		Witness:          nil,
		Sequence:         wire.MaxTxInSequenceNum,
	})
	spendPkScript, err := common.P2TRScriptFromPubKey(aliceConfig.IdentityPublicKey())
	require.NoError(t, err)
	spendTx.AddTxOut(wire.NewTxOut(int64(quoteAmount), spendPkScript))

	// *********************************************************************************
	// Create request signature
	// *********************************************************************************
	spendTxSighash, err := common.SigHashFromTx(
		spendTx,
		0,
		signedDepositTx.TxOut[vout],
	)
	require.NoError(t, err)
	userSignature, err := createUserSignature(
		signedDepositTx.TxHash().String(),
		uint32(vout),
		common.Regtest,
		pb.UtxoSwapRequestType_Refund,
		quoteAmount,
		spendTxSighash[:],
		aliceConfig.IdentityPrivateKey.ToBTCEC(),
	)
	require.NoError(t, err)

	// *********************************************************************************
	// Refund Static Deposit
	// *********************************************************************************
	signedSpendTx, err := wallet.RefundStaticDeposit(
		aliceCtx,
		aliceConfig,
		common.Regtest,
		spendTx,
		aliceDepositPrivKey.ToBTCEC(),
		userSignature,
		aliceConfig.IdentityPublicKey().ToBTCEC(),
		signedDepositTx.TxOut[vout],
		aliceConn,
	)
	require.NoError(t, err)

	spendTxBytes, err := common.SerializeTx(signedSpendTx)
	require.NoError(t, err)
	require.NotEmpty(t, spendTxBytes)

	// Sign, broadcast, and mine spend tx
	txID, err := bitcoinClient.SendRawTransaction(signedSpendTx, true)
	require.NoError(t, err)
	assert.Len(t, txID, 32)

	// *********************************************************************************
	// Refunding a Static Deposit again to another address produces another transaction
	// *********************************************************************************
	spendTx2 := wire.NewMsgTx(2)
	spendTx2.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *depositOutPoint,
		SignatureScript:  nil,
		Witness:          nil,
		Sequence:         wire.MaxTxInSequenceNum,
	})
	pubkeyBytes, err := hex.DecodeString("0252f2cfa8d1f87718c0f3f61b581b7a3dce6bf9a14efd0a501d8969d6ace73a3d")
	require.NoError(t, err)
	withdrawalPubKey, err := keys.ParsePublicKey(pubkeyBytes)
	require.NoError(t, err)
	spendPkScript2, err := common.P2TRScriptFromPubKey(withdrawalPubKey)
	require.NoError(t, err)
	spendTx2.AddTxOut(wire.NewTxOut(int64(quoteAmount), spendPkScript2))

	spendTxSighash2, err := common.SigHashFromTx(
		spendTx2,
		0,
		signedDepositTx.TxOut[vout],
	)
	require.NoError(t, err)
	userSignature2, err := createUserSignature(
		signedDepositTx.TxHash().String(),
		uint32(vout),
		common.Regtest,
		pb.UtxoSwapRequestType_Refund,
		quoteAmount,
		spendTxSighash2[:],
		aliceConfig.IdentityPrivateKey.ToBTCEC(),
	)
	require.NoError(t, err)

	signedSpendTx2, err := wallet.RefundStaticDeposit(
		aliceCtx,
		aliceConfig,
		common.Regtest,
		spendTx2,
		aliceDepositPrivKey.ToBTCEC(),
		userSignature2,
		aliceConfig.IdentityPublicKey().ToBTCEC(),
		signedDepositTx.TxOut[vout],
		aliceConn,
	)
	require.NoError(t, err)
	spendTxBytes2, err := common.SerializeTx(signedSpendTx2)
	require.NoError(t, err)
	assert.NotEqual(t, spendTxBytes, spendTxBytes2)

	// *********************************************************************************
	// A call to rollback should fail
	// *********************************************************************************
	sparkInternalClient := pbinternal.NewSparkInternalServiceClient(aliceConn)
	rollbackUtxoSwapRequestMessageHash, err := handler.CreateUtxoSwapStatement(
		handler.UtxoSwapStatementTypeRollback,
		hex.EncodeToString(depositOutPoint.Hash[:]),
		depositOutPoint.Index,
		common.Regtest,
	)
	require.NoError(t, err)
	rollbackUtxoSwapRequestSignature := ecdsa.Sign(aliceConfig.IdentityPrivateKey.ToBTCEC(), rollbackUtxoSwapRequestMessageHash)

	_, err = sparkInternalClient.RollbackUtxoSwap(aliceCtx, &pbinternal.RollbackUtxoSwapRequest{
		OnChainUtxo: &pb.UTXO{
			Txid:    depositOutPoint.Hash[:],
			Vout:    depositOutPoint.Index,
			Network: pb.Network_REGTEST,
		},
		Signature:            rollbackUtxoSwapRequestSignature.Serialize(),
		CoordinatorPublicKey: aliceConfig.IdentityPublicKey().Serialize(),
	})
	require.Error(t, err)

	// *********************************************************************************
	// A call to RefundStaticDeposit should fail if the caller is not the owner of the utxo swap
	// *********************************************************************************
	bobConfig, err := testutil.TestWalletConfig()
	require.NoError(t, err)

	bobLeafPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	_, err = testutil.CreateNewTree(bobConfig, faucet, bobLeafPrivKey, 100_000)
	require.NoError(t, err)

	bobConn, err := common.NewGRPCConnectionWithTestTLS(bobConfig.CoodinatorAddress(), nil)
	require.NoError(t, err)
	defer bobConn.Close()

	bobConnectionToken, err := wallet.AuthenticateWithConnection(context.Background(), bobConfig, bobConn)
	require.NoError(t, err)
	bobCtx := wallet.ContextWithToken(context.Background(), bobConnectionToken)

	_, err = wallet.RefundStaticDeposit(
		bobCtx,
		bobConfig,
		common.Regtest,
		spendTx2,
		aliceDepositPrivKey.ToBTCEC(),
		userSignature2,
		aliceConfig.IdentityPublicKey().ToBTCEC(),
		signedDepositTx.TxOut[vout],
		bobConn,
	)
	require.ErrorContains(t, err, "utxo swap is already completed by another user")
}
