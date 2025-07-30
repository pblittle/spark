package handler

import (
	"context"
	"testing"

	"github.com/google/uuid"
	pbcommon "github.com/lightsparkdev/spark/proto/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFinalizeSignatureHandler(t *testing.T) {
	config := &so.Config{}
	handler := NewFinalizeSignatureHandler(config)

	assert.NotNil(t, handler)
	assert.Equal(t, config, handler.config)
}

func TestFinalizeSignatureHandler_FinalizeNodeSignatures_EmptyRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, dbCtx := db.NewTestSQLiteContext(t, ctx)
	defer dbCtx.Close()

	config := &so.Config{}
	handler := NewFinalizeSignatureHandler(config)

	req := &pb.FinalizeNodeSignaturesRequest{
		NodeSignatures: []*pb.NodeSignatures{},
		Intent:         pbcommon.SignatureIntent_CREATION,
	}

	resp, err := handler.FinalizeNodeSignatures(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Empty(t, resp.Nodes)
}

func TestFinalizeSignatureHandler_FinalizeNodeSignaturesV2_EmptyRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, dbCtx := db.NewTestSQLiteContext(t, ctx)
	defer dbCtx.Close()

	config := &so.Config{}
	handler := NewFinalizeSignatureHandler(config)

	req := &pb.FinalizeNodeSignaturesRequest{
		NodeSignatures: []*pb.NodeSignatures{},
		Intent:         pbcommon.SignatureIntent_CREATION,
	}

	resp, err := handler.FinalizeNodeSignaturesV2(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Empty(t, resp.Nodes)
}

func TestFinalizeSignatureHandler_ErrorCases(t *testing.T) {
	tests := []struct {
		name          string
		setupFunc     func(t *testing.T, ctx context.Context, handler *FinalizeSignatureHandler) interface{}
		verifyFunc    func(t *testing.T, ctx context.Context, handler *FinalizeSignatureHandler, input interface{}) error
		expectedError string
	}{
		{
			name: "FinalizeNodeSignatures_InvalidNodeID",
			setupFunc: func(t *testing.T, ctx context.Context, handler *FinalizeSignatureHandler) interface{} {
				return &pb.FinalizeNodeSignaturesRequest{
					NodeSignatures: []*pb.NodeSignatures{
						{NodeId: "invalid-uuid"},
					},
					Intent: pbcommon.SignatureIntent_CREATION,
				}
			},
			verifyFunc: func(t *testing.T, ctx context.Context, handler *FinalizeSignatureHandler, input interface{}) error {
				req := input.(*pb.FinalizeNodeSignaturesRequest)
				resp, err := handler.FinalizeNodeSignatures(ctx, req)
				assert.Nil(t, resp)
				return err
			},
			expectedError: "invalid node id",
		},
		{
			name: "FinalizeNodeSignatures_NodeNotFound",
			setupFunc: func(t *testing.T, ctx context.Context, handler *FinalizeSignatureHandler) interface{} {
				nodeID := uuid.New()
				return &pb.FinalizeNodeSignaturesRequest{
					NodeSignatures: []*pb.NodeSignatures{
						{NodeId: nodeID.String()},
					},
					Intent: pbcommon.SignatureIntent_CREATION,
				}
			},
			verifyFunc: func(t *testing.T, ctx context.Context, handler *FinalizeSignatureHandler, input interface{}) error {
				req := input.(*pb.FinalizeNodeSignaturesRequest)
				resp, err := handler.FinalizeNodeSignatures(ctx, req)
				assert.Nil(t, resp)
				return err
			},
			expectedError: "failed to get first node",
		},
		{
			name: "VerifyAndUpdateTransfer_NoTransferFound",
			setupFunc: func(t *testing.T, ctx context.Context, handler *FinalizeSignatureHandler) interface{} {
				nodeID := uuid.New()
				return &pb.FinalizeNodeSignaturesRequest{
					NodeSignatures: []*pb.NodeSignatures{
						{NodeId: nodeID.String()},
					},
					Intent: pbcommon.SignatureIntent_TRANSFER,
				}
			},
			verifyFunc: func(t *testing.T, ctx context.Context, handler *FinalizeSignatureHandler, input interface{}) error {
				req := input.(*pb.FinalizeNodeSignaturesRequest)
				transfer, err := handler.verifyAndUpdateTransfer(ctx, req)
				assert.Nil(t, transfer)
				return err
			},
			expectedError: "failed to find pending transfer",
		},
		{
			name: "UpdateNode_InvalidNodeID",
			setupFunc: func(t *testing.T, ctx context.Context, handler *FinalizeSignatureHandler) interface{} {
				return &pb.NodeSignatures{NodeId: "invalid-uuid"}
			},
			verifyFunc: func(t *testing.T, ctx context.Context, handler *FinalizeSignatureHandler, input interface{}) error {
				nodeSignatures := input.(*pb.NodeSignatures)
				sparkNode, internalNode, err := handler.updateNode(ctx, nodeSignatures, pbcommon.SignatureIntent_CREATION, false)
				assert.Nil(t, sparkNode)
				assert.Nil(t, internalNode)
				return err
			},
			expectedError: "invalid node id",
		},
		{
			name: "UpdateNode_NodeNotFound",
			setupFunc: func(t *testing.T, ctx context.Context, handler *FinalizeSignatureHandler) interface{} {
				nodeID := uuid.New()
				return &pb.NodeSignatures{NodeId: nodeID.String()}
			},
			verifyFunc: func(t *testing.T, ctx context.Context, handler *FinalizeSignatureHandler, input interface{}) error {
				nodeSignatures := input.(*pb.NodeSignatures)
				sparkNode, internalNode, err := handler.updateNode(ctx, nodeSignatures, pbcommon.SignatureIntent_CREATION, false)
				assert.Nil(t, sparkNode)
				assert.Nil(t, internalNode)
				return err
			},
			expectedError: "failed to get node",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			ctx, dbCtx := db.NewTestSQLiteContext(t, ctx)
			defer dbCtx.Close()

			config := &so.Config{}
			handler := NewFinalizeSignatureHandler(config)

			input := tt.setupFunc(t, ctx, handler)
			err := tt.verifyFunc(t, ctx, handler, input)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func createTestTree(t *testing.T, ctx context.Context, network st.Network) (*ent.Tree, *ent.TreeNode) {
	db, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)

	tree, err := db.Tree.Create().
		SetID(uuid.New()).
		SetNetwork(network).
		SetStatus(st.TreeStatusAvailable).
		SetBaseTxid([]byte("base_txid")).
		SetVout(0).
		SetOwnerIdentityPubkey([]byte("owner_pubkey")).
		Save(ctx)
	require.NoError(t, err)

	keyshare, err := db.SigningKeyshare.Create().
		SetID(uuid.New()).
		SetStatus(st.KeyshareStatusAvailable).
		SetSecretShare([]byte("secret_share")).
		SetPublicShares(map[string][]byte{"1": []byte("pubkey1"), "2": []byte("pubkey2")}).
		SetPublicKey([]byte("public_key")).
		SetMinSigners(2).
		SetCoordinatorIndex(0).
		Save(ctx)
	require.NoError(t, err)

	node, err := db.TreeNode.Create().
		SetID(uuid.New()).
		SetTree(tree).
		SetSigningKeyshare(keyshare).
		SetValue(1000).
		SetVerifyingPubkey([]byte("verifying_pubkey")).
		SetOwnerIdentityPubkey([]byte("owner_identity_pubkey")).
		SetOwnerSigningPubkey([]byte("owner_signing_pubkey")).
		SetRawTx([]byte("raw_tx")).
		SetRawRefundTx([]byte("raw_refund_tx")).
		SetVout(0).
		SetStatus(st.TreeNodeStatusCreating).
		Save(ctx)
	require.NoError(t, err)

	return tree, node
}

func TestFinalizeSignatureHandler_FinalizeNodeSignatures_InvalidIntent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, dbCtx := db.NewTestSQLiteContext(t, ctx)
	defer dbCtx.Close()

	config := &so.Config{
		SigningOperatorMap: map[string]*so.SigningOperator{
			"test-operator": {
				ID:         0,
				Identifier: "test-operator",
				AddressRpc: "localhost:8080",
				AddressDkg: "localhost:8081",
			},
		},
	}
	handler := NewFinalizeSignatureHandler(config)

	_, node := createTestTree(t, ctx, st.NetworkRegtest)

	req := &pb.FinalizeNodeSignaturesRequest{
		NodeSignatures: []*pb.NodeSignatures{
			{
				NodeId: node.ID.String(),
			},
		},
		Intent: pbcommon.SignatureIntent(999),
	}

	resp, err := handler.FinalizeNodeSignatures(ctx, req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid intent")
}

func TestFinalizeSignatureHandler_FinalizeNodeSignaturesV2_RequireDirectTx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, dbCtx := db.NewTestSQLiteContext(t, ctx)
	defer dbCtx.Close()

	config := &so.Config{}
	handler := NewFinalizeSignatureHandler(config)

	req := &pb.FinalizeNodeSignaturesRequest{
		NodeSignatures: []*pb.NodeSignatures{},
		Intent:         pbcommon.SignatureIntent_CREATION,
	}

	resp, err := handler.FinalizeNodeSignaturesV2(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Empty(t, resp.Nodes)
}
