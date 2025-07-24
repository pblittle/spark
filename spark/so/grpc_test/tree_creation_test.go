package grpctest

import (
	"bytes"
	"context"
	"encoding/hex"
	"log"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	testutil "github.com/lightsparkdev/spark/test_util"
	"github.com/lightsparkdev/spark/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTreeCreationAddressGeneration(t *testing.T) {
	config, err := testutil.TestWalletConfig()
	require.NoError(t, err)

	// Setup Mock tx
	conn, err := common.NewGRPCConnectionWithTestTLS(config.CoodinatorAddress(), nil)
	require.NoError(t, err, "failed to connect to operator")
	defer conn.Close()

	token, err := wallet.AuthenticateWithConnection(context.Background(), config, conn)
	require.NoError(t, err, "failed to authenticate")
	ctx := wallet.ContextWithToken(context.Background(), token)

	privKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	userPubKey := privKey.PubKey()
	userPubKeyBytes := userPubKey.SerializeCompressed()

	leafID := uuid.New().String()
	depositResp, err := wallet.GenerateDepositAddress(ctx, config, userPubKeyBytes, &leafID, false)
	require.NoError(t, err, "failed to generate deposit address")

	depositTx, err := testutil.CreateTestP2TRTransaction(depositResp.DepositAddress.Address, 65536)
	require.NoError(t, err)
	vout := 0
	var buf bytes.Buffer
	err = depositTx.Serialize(&buf)
	require.NoError(t, err)
	depositTxHex := hex.EncodeToString(buf.Bytes())
	decodedBytes, err := hex.DecodeString(depositTxHex)
	require.NoError(t, err)
	depositTx, err = common.TxFromRawTxBytes(decodedBytes)
	require.NoError(t, err)

	log.Printf("deposit public key: %x", hex.EncodeToString(privKey.PubKey().SerializeCompressed()))
	tree, err := wallet.GenerateDepositAddressesForTree(ctx, config, depositTx, nil, uint32(vout), privKey.Serialize(), 3)
	require.NoError(t, err)

	log.Printf("tree created: %v", tree)

	treeNodes, err := wallet.CreateTree(ctx, config, depositTx, nil, uint32(vout), tree, true)
	require.NoError(t, err)

	log.Printf("tree nodes created: %v", treeNodes)
}

func TestTreeCreationWithMultiLevels(t *testing.T) {
	config, err := testutil.TestWalletConfig()
	require.NoError(t, err)

	conn, err := common.NewGRPCConnectionWithTestTLS(config.CoodinatorAddress(), nil)
	require.NoError(t, err)
	defer conn.Close()

	token, err := wallet.AuthenticateWithConnection(context.Background(), config, conn)
	require.NoError(t, err)
	ctx := wallet.ContextWithToken(context.Background(), token)

	privKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	userPubKey := privKey.PubKey()
	userPubKeyBytes := userPubKey.SerializeCompressed()

	leafID := uuid.New().String()
	depositResp, err := wallet.GenerateDepositAddress(ctx, config, userPubKeyBytes, &leafID, false)
	require.NoError(t, err)

	client := testutil.GetBitcoinClient()

	coin, err := faucet.Fund()
	require.NoError(t, err)
	depositTx, err := testutil.CreateTestDepositTransaction(coin.OutPoint, depositResp.DepositAddress.Address, 65536)
	require.NoError(t, err)
	vout := 0
	var buf bytes.Buffer
	require.NoError(t, depositTx.Serialize(&buf))
	depositTxHex := hex.EncodeToString(buf.Bytes())
	decodedBytes, err := hex.DecodeString(depositTxHex)
	require.NoError(t, err)
	depositTx, err = common.TxFromRawTxBytes(decodedBytes)
	require.NoError(t, err)

	log.Printf("deposit public key: %x", hex.EncodeToString(privKey.PubKey().SerializeCompressed()))
	tree, err := wallet.GenerateDepositAddressesForTree(ctx, config, depositTx, nil, uint32(vout), privKey.Serialize(), 2)
	require.NoError(t, err)

	log.Printf("tree created: %v", tree)

	treeNodes, err := wallet.CreateTree(ctx, config, depositTx, nil, uint32(vout), tree, false)
	require.NoError(t, err)

	assert.Len(t, treeNodes.Nodes, 3)

	for i, node := range treeNodes.Nodes {
		if i == 0 {
			continue
		}
		leftPrivKeyBytes := tree.Children[i-1].Children[0].SigningPrivateKey
		leftAddress, err := wallet.GenerateDepositAddressesForTree(ctx, config, nil, node, 0, leftPrivKeyBytes, 2)
		require.NoError(t, err)
		_, err = wallet.CreateTree(ctx, config, nil, node, 0, leftAddress, true)
		require.NoError(t, err)

		rightPrivKeyBytes := tree.Children[i-1].Children[1].SigningPrivateKey
		rightAddress, err := wallet.GenerateDepositAddressesForTree(ctx, config, nil, node, 1, rightPrivKeyBytes, 2)
		require.NoError(t, err)
		_, err = wallet.CreateTree(ctx, config, nil, node, 1, rightAddress, true)
		require.NoError(t, err)

	}

	for _, node := range treeNodes.Nodes {
		assert.Equal(t, string(st.TreeNodeStatusCreating), node.Status)
	}

	// Sign, broadcast, and mine deposit tx
	signedDepositTx, err := testutil.SignFaucetCoin(depositTx, coin.TxOut, coin.Key)
	require.NoError(t, err)
	log.Printf("signed deposit tx: %s", signedDepositTx.TxHash().String())
	_, err = client.SendRawTransaction(signedDepositTx, true)
	require.NoError(t, err)

	randomKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	randomPubKey := randomKey.PubKey()
	randomAddress, err := common.P2TRRawAddressFromPublicKey(randomPubKey.SerializeCompressed(), common.Regtest)
	require.NoError(t, err)
	_, err = client.GenerateToAddress(1, randomAddress, nil)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	sparkClient := pb.NewSparkServiceClient(conn)

	network, err := common.ProtoNetworkFromNetwork(config.Network)
	require.NoError(t, err)
	response, err := sparkClient.QueryNodes(ctx, &pb.QueryNodesRequest{
		Source:         &pb.QueryNodesRequest_OwnerIdentityPubkey{OwnerIdentityPubkey: config.IdentityPublicKey()},
		IncludeParents: true,
		Network:        network,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, response.Nodes)
}

func TestTreeCreationSplitMultipleTimes(t *testing.T) {
	config, err := testutil.TestWalletConfig()
	require.NoError(t, err)

	conn, err := common.NewGRPCConnectionWithTestTLS(config.CoodinatorAddress(), nil)
	require.NoError(t, err)
	defer conn.Close()

	token, err := wallet.AuthenticateWithConnection(context.Background(), config, conn)
	require.NoError(t, err)
	ctx := wallet.ContextWithToken(context.Background(), token)

	privKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	userPubKey := privKey.PubKey()
	userPubKeyBytes := userPubKey.SerializeCompressed()

	leafID := uuid.New().String()
	depositResp, err := wallet.GenerateDepositAddress(ctx, config, userPubKeyBytes, &leafID, false)
	require.NoError(t, err)

	depositTx, err := testutil.CreateTestP2TRTransaction(depositResp.DepositAddress.Address, 65536)
	require.NoError(t, err)
	vout := 0
	var buf bytes.Buffer
	err = depositTx.Serialize(&buf)
	require.NoError(t, err)
	depositTxHex := hex.EncodeToString(buf.Bytes())
	decodedBytes, err := hex.DecodeString(depositTxHex)
	require.NoError(t, err)
	depositTx, err = common.TxFromRawTxBytes(decodedBytes)
	require.NoError(t, err)

	log.Printf("deposit public key: %x", hex.EncodeToString(privKey.PubKey().SerializeCompressed()))
	tree, err := wallet.GenerateDepositAddressesForTree(ctx, config, depositTx, nil, uint32(vout), privKey.Serialize(), 2)
	require.NoError(t, err)

	log.Printf("tree created: %v", tree)

	treeNodes, err := wallet.CreateTree(ctx, config, depositTx, nil, uint32(vout), tree, false)
	require.NoError(t, err)

	assert.Len(t, treeNodes.Nodes, 3)

	_, err = wallet.GenerateDepositAddressesForTree(ctx, config, depositTx, nil, uint32(vout), privKey.Serialize(), 2)
	require.Error(t, err)

	for i, node := range treeNodes.Nodes {
		if i == 0 {
			continue
		}
		leftPrivKeyBytes := tree.Children[i-1].Children[0].SigningPrivateKey
		leftAddress, err := wallet.GenerateDepositAddressesForTree(ctx, config, nil, node, 0, leftPrivKeyBytes, 2)
		require.NoError(t, err)
		_, err = wallet.CreateTree(ctx, config, nil, node, 0, leftAddress, true)
		require.NoError(t, err)

		rightPrivKeyBytes := tree.Children[i-1].Children[1].SigningPrivateKey
		rightAddress, err := wallet.GenerateDepositAddressesForTree(ctx, config, nil, node, 1, rightPrivKeyBytes, 2)
		require.NoError(t, err)
		_, err = wallet.CreateTree(ctx, config, nil, node, 1, rightAddress, true)
		require.NoError(t, err)
	}

	for i, node := range treeNodes.Nodes {
		if i == 0 {
			continue
		}
		leftPrivKeyBytes := tree.Children[i-1].Children[0].SigningPrivateKey
		// Check that, if you create a tree on a leaf that has already created the subtree, it will fail the call
		_, err := wallet.GenerateDepositAddressesForTree(ctx, config, nil, node, 0, leftPrivKeyBytes, 2)
		require.Error(t, err)

		rightPrivKeyBytes := tree.Children[i-1].Children[1].SigningPrivateKey
		_, err = wallet.GenerateDepositAddressesForTree(ctx, config, nil, node, 1, rightPrivKeyBytes, 2)
		require.Error(t, err)
	}
}
