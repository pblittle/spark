package grpc

import (
	"context"
	"fmt"

	"github.com/lightsparkdev/spark/so/protoconverter"

	"github.com/lightsparkdev/spark/so/handler/tokens"

	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/logging"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/errors"
	"github.com/lightsparkdev/spark/so/handler"
	events "github.com/lightsparkdev/spark/so/stream"
	"google.golang.org/protobuf/types/known/emptypb"
)

// SparkServer is the grpc server for the Spark protocol.
// It will be used by the user or Spark service provider.
type SparkServer struct {
	pb.UnimplementedSparkServiceServer
	config     *so.Config
	mockAction *common.MockAction
}

var emptyResponse = &emptypb.Empty{}

// NewSparkServer creates a new SparkServer.
func NewSparkServer(config *so.Config, mockAction *common.MockAction) *SparkServer {
	return &SparkServer{config: config, mockAction: mockAction}
}

// GenerateDepositAddress generates a deposit address for the given public key.
func (s *SparkServer) GenerateDepositAddress(ctx context.Context, req *pb.GenerateDepositAddressRequest) (*pb.GenerateDepositAddressResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.IdentityPublicKey)
	depositHandler := handler.NewDepositHandler(s.config)
	return errors.WrapWithGRPCError(depositHandler.GenerateDepositAddress(ctx, s.config, req))
}

// StartDepositTreeCreation verifies the on chain utxo, and then verifies and signs the offchain root and refund transactions.
func (s *SparkServer) StartDepositTreeCreation(ctx context.Context, req *pb.StartDepositTreeCreationRequest) (*pb.StartDepositTreeCreationResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.IdentityPublicKey)
	depositHandler := handler.NewDepositHandler(s.config)
	return errors.WrapWithGRPCError(depositHandler.StartDepositTreeCreation(ctx, s.config, req))
}

// This is deprecated, please use StartDepsitTreeCreation instead.
func (s *SparkServer) StartTreeCreation(ctx context.Context, req *pb.StartTreeCreationRequest) (*pb.StartTreeCreationResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.IdentityPublicKey)
	depositHandler := handler.NewDepositHandler(s.config)
	return errors.WrapWithGRPCError(depositHandler.StartTreeCreation(ctx, s.config, req))
}

// FinalizeNodeSignatures verifies the node signatures and updates the node.
func (s *SparkServer) FinalizeNodeSignatures(ctx context.Context, req *pb.FinalizeNodeSignaturesRequest) (*pb.FinalizeNodeSignaturesResponse, error) {
	finalizeSignatureHandler := handler.NewFinalizeSignatureHandler(s.config)
	return errors.WrapWithGRPCError(finalizeSignatureHandler.FinalizeNodeSignatures(ctx, req))
}

// FinalizeNodeSignatures verifies the node signatures and updates the node.
func (s *SparkServer) FinalizeNodeSignaturesV2(ctx context.Context, req *pb.FinalizeNodeSignaturesRequest) (*pb.FinalizeNodeSignaturesResponse, error) {
	finalizeSignatureHandler := handler.NewFinalizeSignatureHandler(s.config)
	return errors.WrapWithGRPCError(finalizeSignatureHandler.FinalizeNodeSignaturesV2(ctx, req))
}

// StartTransfer initiates a transfer from sender.
func (s *SparkServer) StartTransfer(ctx context.Context, req *pb.StartTransferRequest) (*pb.StartTransferResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.OwnerIdentityPublicKey)
	transferHander := handler.NewTransferHandler(s.config)
	return errors.WrapWithGRPCError(transferHander.StartTransfer(ctx, req))
}

// StartTransfer initiates a transfer from sender.
func (s *SparkServer) StartTransferV2(ctx context.Context, req *pb.StartTransferRequest) (*pb.StartTransferResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.OwnerIdentityPublicKey)
	transferHander := handler.NewTransferHandler(s.config)
	return errors.WrapWithGRPCError(transferHander.StartTransferV2(ctx, req))
}

// FinalizeTransfer completes a transfer from sender.
func (s *SparkServer) FinalizeTransfer(ctx context.Context, req *pb.FinalizeTransferRequest) (*pb.FinalizeTransferResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.OwnerIdentityPublicKey)
	transferHander := handler.NewTransferHandler(s.config)
	return errors.WrapWithGRPCError(transferHander.FinalizeTransfer(ctx, req))
}

func (s *SparkServer) FinalizeTransferWithTransferPackage(ctx context.Context, req *pb.FinalizeTransferWithTransferPackageRequest) (*pb.FinalizeTransferResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.OwnerIdentityPublicKey)
	transferHandler := handler.NewTransferHandler(s.config)
	return errors.WrapWithGRPCError(transferHandler.FinalizeTransferWithTransferPackage(ctx, req))
}

// CancelTransfer cancels a transfer from sender before key is tweaked.
func (s *SparkServer) CancelTransfer(ctx context.Context, req *pb.CancelTransferRequest) (*pb.CancelTransferResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.SenderIdentityPublicKey)
	transferHander := handler.NewTransferHandler(s.config)
	return errors.WrapWithGRPCError(transferHander.CancelTransfer(ctx, req))
}

// QueryPendingTransfers queries the pending transfers to claim.
func (s *SparkServer) QueryPendingTransfers(ctx context.Context, req *pb.TransferFilter) (*pb.QueryTransfersResponse, error) {
	transferHander := handler.NewTransferHandler(s.config)
	return errors.WrapWithGRPCError(transferHander.QueryPendingTransfers(ctx, req))
}

// ClaimTransferTweakKeys starts claiming a pending transfer by tweaking keys of leaves.
func (s *SparkServer) ClaimTransferTweakKeys(ctx context.Context, req *pb.ClaimTransferTweakKeysRequest) (*emptypb.Empty, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.OwnerIdentityPublicKey)
	transferHander := handler.NewTransferHandler(s.config)
	return errors.WrapWithGRPCError(emptyResponse, transferHander.ClaimTransferTweakKeys(ctx, req))
}

// ClaimTransferSignRefunds signs new refund transactions as part of the transfer.
func (s *SparkServer) ClaimTransferSignRefundsV2(ctx context.Context, req *pb.ClaimTransferSignRefundsRequest) (*pb.ClaimTransferSignRefundsResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.OwnerIdentityPublicKey)
	transferHander := handler.NewTransferHandler(s.config)
	if s.mockAction != nil {
		transferHander.SetMockAction(s.mockAction)
	}
	return errors.WrapWithGRPCError(transferHander.ClaimTransferSignRefundsV2(ctx, req))
}

// ClaimTransferSignRefunds signs new refund transactions as part of the transfer.
func (s *SparkServer) ClaimTransferSignRefunds(ctx context.Context, req *pb.ClaimTransferSignRefundsRequest) (*pb.ClaimTransferSignRefundsResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.OwnerIdentityPublicKey)
	transferHander := handler.NewTransferHandler(s.config)
	if s.mockAction != nil {
		transferHander.SetMockAction(s.mockAction)
	}
	return errors.WrapWithGRPCError(transferHander.ClaimTransferSignRefunds(ctx, req))
}

// StorePreimageShare stores the preimage share for the given payment hash.
func (s *SparkServer) StorePreimageShare(ctx context.Context, req *pb.StorePreimageShareRequest) (*emptypb.Empty, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.UserIdentityPublicKey)
	lightningHandler := handler.NewLightningHandler(s.config)
	return errors.WrapWithGRPCError(emptyResponse, lightningHandler.StorePreimageShare(ctx, req))
}

// GetSigningCommitments gets the signing commitments for the given node ids.
func (s *SparkServer) GetSigningCommitments(ctx context.Context, req *pb.GetSigningCommitmentsRequest) (*pb.GetSigningCommitmentsResponse, error) {
	lightningHandler := handler.NewLightningHandler(s.config)
	return errors.WrapWithGRPCError(lightningHandler.GetSigningCommitments(ctx, req))
}

// InitiatePreimageSwap initiates a preimage swap for the given payment hash.
func (s *SparkServer) InitiatePreimageSwap(ctx context.Context, req *pb.InitiatePreimageSwapRequest) (*pb.InitiatePreimageSwapResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.Transfer.OwnerIdentityPublicKey)
	lightningHandler := handler.NewLightningHandler(s.config)
	return errors.WrapWithGRPCError(lightningHandler.InitiatePreimageSwap(ctx, req))
}

// InitiatePreimageSwap initiates a preimage swap for the given payment hash.
func (s *SparkServer) InitiatePreimageSwapV2(ctx context.Context, req *pb.InitiatePreimageSwapRequest) (*pb.InitiatePreimageSwapResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.Transfer.OwnerIdentityPublicKey)
	lightningHandler := handler.NewLightningHandler(s.config)
	return errors.WrapWithGRPCError(lightningHandler.InitiatePreimageSwapV2(ctx, req))
}

// CooperativeExit asks for signatures for refund transactions spending leaves
// and connector outputs on another user's L1 transaction.
func (s *SparkServer) CooperativeExit(ctx context.Context, req *pb.CooperativeExitRequest) (*pb.CooperativeExitResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.Transfer.OwnerIdentityPublicKey)
	coopExitHandler := handler.NewCooperativeExitHandler(s.config)
	return errors.WrapWithGRPCError(coopExitHandler.CooperativeExit(ctx, req))
}

// Same as above, but enforces use of direct transactions for unilateral exits
func (s *SparkServer) CooperativeExitV2(ctx context.Context, req *pb.CooperativeExitRequest) (*pb.CooperativeExitResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.Transfer.OwnerIdentityPublicKey)
	coopExitHandler := handler.NewCooperativeExitHandler(s.config)
	return errors.WrapWithGRPCError(coopExitHandler.CooperativeExit(ctx, req))
}

// StartLeafSwap initiates a swap of leaves between two users.
func (s *SparkServer) StartLeafSwap(ctx context.Context, req *pb.StartTransferRequest) (*pb.StartTransferResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.OwnerIdentityPublicKey)
	transferHander := handler.NewTransferHandler(s.config)
	return errors.WrapWithGRPCError(transferHander.StartLeafSwap(ctx, req))
}

// StartLeafSwap initiates a swap of leaves between two users.
func (s *SparkServer) StartLeafSwapV2(ctx context.Context, req *pb.StartTransferRequest) (*pb.StartTransferResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.OwnerIdentityPublicKey)
	transferHander := handler.NewTransferHandler(s.config)
	return errors.WrapWithGRPCError(transferHander.StartLeafSwapV2(ctx, req))
}

// LeafSwap starts the reverse side of a swap of leaves between two users.
// This is deprecated but remains for backwards compatibility,
// CounterLeafSwap should be used instead.
func (s *SparkServer) LeafSwap(ctx context.Context, req *pb.CounterLeafSwapRequest) (*pb.CounterLeafSwapResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.Transfer.OwnerIdentityPublicKey)
	transferHander := handler.NewTransferHandler(s.config)
	return errors.WrapWithGRPCError(transferHander.CounterLeafSwap(ctx, req))
}

// CounterLeafSwap starts the reverse side of a swap of leaves between two users.
func (s *SparkServer) CounterLeafSwap(ctx context.Context, req *pb.CounterLeafSwapRequest) (*pb.CounterLeafSwapResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.Transfer.OwnerIdentityPublicKey)
	transferHander := handler.NewTransferHandler(s.config)
	return errors.WrapWithGRPCError(transferHander.CounterLeafSwap(ctx, req))
}

// CounterLeafSwap starts the reverse side of a swap of leaves between two users.
func (s *SparkServer) CounterLeafSwapV2(ctx context.Context, req *pb.CounterLeafSwapRequest) (*pb.CounterLeafSwapResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.Transfer.OwnerIdentityPublicKey)
	transferHander := handler.NewTransferHandler(s.config)
	return errors.WrapWithGRPCError(transferHander.CounterLeafSwapV2(ctx, req))
}

// RefreshTimelock refreshes the timelocks of a leaf and its ancestors.
func (s *SparkServer) RefreshTimelock(ctx context.Context, req *pb.RefreshTimelockRequest) (*pb.RefreshTimelockResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.OwnerIdentityPublicKey)
	timelockHandler := handler.NewRefreshTimelockHandler(s.config)
	return errors.WrapWithGRPCError(timelockHandler.RefreshTimelock(ctx, req))
}

// Same as above, but requires direct TX to be included
func (s *SparkServer) RefreshTimelockV2(ctx context.Context, req *pb.RefreshTimelockRequest) (*pb.RefreshTimelockResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.OwnerIdentityPublicKey)
	handler := handler.NewRefreshTimelockHandler(s.config)
	return errors.WrapWithGRPCError(handler.RefreshTimelockV2(ctx, req))
}

func (s *SparkServer) ExtendLeaf(ctx context.Context, req *pb.ExtendLeafRequest) (*pb.ExtendLeafResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.OwnerIdentityPublicKey)
	leafHandler := handler.NewExtendLeafHandler(s.config)
	return errors.WrapWithGRPCError(leafHandler.ExtendLeaf(ctx, req))
}

func (s *SparkServer) ExtendLeafV2(ctx context.Context, req *pb.ExtendLeafRequest) (*pb.ExtendLeafResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.OwnerIdentityPublicKey)
	handler := handler.NewExtendLeafHandler(s.config)
	return errors.WrapWithGRPCError(handler.ExtendLeafV2(ctx, req))
}

// PrepareTreeAddress prepares the tree address for the given public key.
func (s *SparkServer) PrepareTreeAddress(ctx context.Context, req *pb.PrepareTreeAddressRequest) (*pb.PrepareTreeAddressResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.UserIdentityPublicKey)
	treeHandler := handler.NewTreeCreationHandler(s.config)
	return errors.WrapWithGRPCError(treeHandler.PrepareTreeAddress(ctx, req))
}

// CreateTree creates a tree from user input and signs the transactions in the tree.
func (s *SparkServer) CreateTree(ctx context.Context, req *pb.CreateTreeRequest) (*pb.CreateTreeResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.UserIdentityPublicKey)
	treeHandler := handler.NewTreeCreationHandler(s.config)
	return errors.WrapWithGRPCError(treeHandler.CreateTree(ctx, req))
}

// CreateTreeV2 creates a tree from user input and signs the transactions in the tree.
func (s *SparkServer) CreateTreeV2(ctx context.Context, req *pb.CreateTreeRequest) (*pb.CreateTreeResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.UserIdentityPublicKey)
	treeHandler := handler.NewTreeCreationHandler(s.config)
	return errors.WrapWithGRPCError(treeHandler.CreateTreeV2(ctx, req))
}

// GetSigningOperatorList gets the list of signing operators.
func (s *SparkServer) GetSigningOperatorList(_ context.Context, _ *emptypb.Empty) (*pb.GetSigningOperatorListResponse, error) {
	return &pb.GetSigningOperatorListResponse{SigningOperators: s.config.GetSigningOperatorList()}, nil
}

func (s *SparkServer) QueryUserSignedRefunds(ctx context.Context, req *pb.QueryUserSignedRefundsRequest) (*pb.QueryUserSignedRefundsResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.IdentityPublicKey)
	lightningHandler := handler.NewLightningHandler(s.config)
	return errors.WrapWithGRPCError(lightningHandler.QueryUserSignedRefunds(ctx, req))
}

func (s *SparkServer) ProvidePreimage(ctx context.Context, req *pb.ProvidePreimageRequest) (*pb.ProvidePreimageResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.IdentityPublicKey)
	lightningHandler := handler.NewLightningHandler(s.config)
	return errors.WrapWithGRPCError(lightningHandler.ProvidePreimage(ctx, req))
}

func (s *SparkServer) ReturnLightningPayment(ctx context.Context, req *pb.ReturnLightningPaymentRequest) (*emptypb.Empty, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.UserIdentityPublicKey)
	lightningHandler := handler.NewLightningHandler(s.config)
	return errors.WrapWithGRPCError(lightningHandler.ReturnLightningPayment(ctx, req, false))
}

// StartTokenTransaction reserves revocation keyshares, and fills the revocation commitment (and other SO-derived fields) to create the final token transaction.
func (s *SparkServer) StartTokenTransaction(ctx context.Context, req *pb.StartTokenTransactionRequest) (*pb.StartTokenTransactionResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.IdentityPublicKey)
	tokenTransactionHandler := tokens.NewStartTokenTransactionHandler(s.config)

	network, err := common.NetworkFromProtoNetwork(req.PartialTokenTransaction.Network)
	if err != nil {
		return nil, fmt.Errorf("failed to parse network: %w", err)
	}
	startTransaction, err := protoconverter.TokenProtoStartTransactionRequestFromSpark(req, s.config.Lrc20Configs[network.String()].TransactionExpiryDuration)
	if err != nil {
		return nil, fmt.Errorf("failed to convert request into v0: %w", err)
	}

	startTransactionResponse, err := tokenTransactionHandler.StartTokenTransaction(ctx, startTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to start token transaction: %w", err)
	}

	response, err := protoconverter.SparkStartTokenTransactionResponseFromTokenProto(startTransactionResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to convert request into v0: %w", err)
	}

	return response, nil
}

// QueryNodes queries the details of nodes given either the owner identity public key or a list of node ids.
func (s *SparkServer) QueryNodes(ctx context.Context, req *pb.QueryNodesRequest) (*pb.QueryNodesResponse, error) {
	treeQueryHandler := handler.NewTreeQueryHandler(s.config)
	return errors.WrapWithGRPCError(treeQueryHandler.QueryNodes(ctx, req))
}

// GetTokenTransactionRevocationKeyshares allows the wallet to retrieve the revocation keyshares from each individual SO to
// allow the wallet to combine these shares into the fully resolved revocation secret necessary for transaction finalization.
func (s *SparkServer) SignTokenTransaction(ctx context.Context, req *pb.SignTokenTransactionRequest) (*pb.SignTokenTransactionResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.IdentityPublicKey)
	signTokenHandler := tokens.NewSignTokenHandler(s.config)
	resp, err := signTokenHandler.SignTokenTransaction(ctx, req)
	return errors.WrapWithGRPCError(resp, err)
}

// FinalizeTokenTransaction verifies the revocation secrets constructed by the wallet and passes these keys to the LRC20 Node
// to finalize the transaction. This operation irreversibly spends the inputs associated with the transaction.
func (s *SparkServer) FinalizeTokenTransaction(ctx context.Context, req *pb.FinalizeTokenTransactionRequest) (*emptypb.Empty, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.IdentityPublicKey)
	finalizeTokenHandler := tokens.NewFinalizeTokenHandler(s.config)
	resp, err := finalizeTokenHandler.FinalizeTokenTransaction(ctx, req)
	return errors.WrapWithGRPCError(resp, err)
}

// FreezeTokens prevents transfer of all outputs owned now and in the future by the provided owner public key.
// Unfreeze undos this operation and re-enables transfers.
func (s *SparkServer) FreezeTokens(ctx context.Context, req *pb.FreezeTokensRequest) (*pb.FreezeTokensResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.FreezeTokensPayload.OwnerPublicKey)
	tokenReq := protoconverter.TokenProtoFreezeTokensRequestFromSpark(req)
	freezeTokenHandler := tokens.NewFreezeTokenHandler(s.config)

	tokenRes, err := freezeTokenHandler.FreezeTokens(ctx, tokenReq)
	if err != nil {
		return nil, fmt.Errorf("failed to freeze tokens: %w", err)
	}
	return protoconverter.SparkFreezeTokensResponseFromTokenProto(tokenRes), nil
}

// QueryTokenTransactions returns the token transactions currently owned by the provided owner public key.
func (s *SparkServer) QueryTokenTransactions(ctx context.Context, req *pb.QueryTokenTransactionsRequest) (*pb.QueryTokenTransactionsResponse, error) {
	queryTokenHandler := tokens.NewQueryTokenHandler(s.config)
	resp, err := queryTokenHandler.QueryTokenTransactions(ctx, req)
	return errors.WrapWithGRPCError(resp, err)
}

// QueryTokenOutputs returns the token outputs currently owned by the provided owner public key.
func (s *SparkServer) QueryTokenOutputs(ctx context.Context, req *pb.QueryTokenOutputsRequest) (*pb.QueryTokenOutputsResponse, error) {
	queryTokenHandler := tokens.NewQueryTokenHandler(s.config)
	resp, err := queryTokenHandler.QueryTokenOutputs(ctx, req)
	return errors.WrapWithGRPCError(resp, err)
}

func (s *SparkServer) QueryAllTransfers(ctx context.Context, req *pb.TransferFilter) (*pb.QueryTransfersResponse, error) {
	transferHander := handler.NewTransferHandler(s.config)
	return errors.WrapWithGRPCError(transferHander.QueryAllTransfers(ctx, req))
}

func (s *SparkServer) QueryUnusedDepositAddresses(ctx context.Context, req *pb.QueryUnusedDepositAddressesRequest) (*pb.QueryUnusedDepositAddressesResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.IdentityPublicKey)
	treeQueryHandler := handler.NewTreeQueryHandler(s.config)
	return errors.WrapWithGRPCError(treeQueryHandler.QueryUnusedDepositAddresses(ctx, req))
}

func (s *SparkServer) QueryStaticDepositAddresses(ctx context.Context, req *pb.QueryStaticDepositAddressesRequest) (*pb.QueryStaticDepositAddressesResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.IdentityPublicKey)
	treeQueryHandler := handler.NewTreeQueryHandler(s.config)
	return errors.WrapWithGRPCError(treeQueryHandler.QueryStaticDepositAddresses(ctx, req))
}

func (s *SparkServer) QueryBalance(ctx context.Context, req *pb.QueryBalanceRequest) (*pb.QueryBalanceResponse, error) {
	ctx, _ = logging.WithIdentityPubkey(ctx, req.IdentityPublicKey)
	treeQueryHandler := handler.NewTreeQueryHandler(s.config)
	return errors.WrapWithGRPCError(treeQueryHandler.QueryBalance(ctx, req))
}

func (s *SparkServer) SubscribeToEvents(req *pb.SubscribeToEventsRequest, st pb.SparkService_SubscribeToEventsServer) error {
	return events.SubscribeToEvents(req.IdentityPublicKey, st)
}

// Swap Spark tree node in exchange for an UTXO
func (s *SparkServer) InitiateUtxoSwap(ctx context.Context, req *pb.InitiateUtxoSwapRequest) (*pb.InitiateUtxoSwapResponse, error) {
	depositHandler := handler.NewDepositHandler(s.config)
	return errors.WrapWithGRPCError(depositHandler.InitiateUtxoSwap(ctx, s.config, req))
}

func (s *SparkServer) InitiateStaticDepositUtxoRefund(ctx context.Context, req *pb.InitiateStaticDepositUtxoRefundRequest) (*pb.InitiateStaticDepositUtxoRefundResponse, error) {
	depositHandler := handler.NewStaticDepositHandler(s.config)
	return errors.WrapWithGRPCError(depositHandler.InitiateStaticDepositUtxoRefund(ctx, s.config, req))
}

func (s *SparkServer) ExitSingleNodeTrees(ctx context.Context, req *pb.ExitSingleNodeTreesRequest) (*pb.ExitSingleNodeTreesResponse, error) {
	treeExitHandler := handler.NewTreeExitHandler(s.config)
	return errors.WrapWithGRPCError(treeExitHandler.ExitSingleNodeTrees(ctx, req))
}

func (s *SparkServer) InvestigateLeaves(ctx context.Context, req *pb.InvestigateLeavesRequest) (*emptypb.Empty, error) {
	transferHandler := handler.NewTransferHandler(s.config)
	return errors.WrapWithGRPCError(transferHandler.InvestigateLeaves(ctx, req))
}

func (s *SparkServer) QueryNodesDistribution(ctx context.Context, req *pb.QueryNodesDistributionRequest) (*pb.QueryNodesDistributionResponse, error) {
	treeQueryHandler := handler.NewTreeQueryHandler(s.config)
	return errors.WrapWithGRPCError(treeQueryHandler.QueryNodesDistribution(ctx, req))
}

func (s *SparkServer) QueryNodesByValue(ctx context.Context, req *pb.QueryNodesByValueRequest) (*pb.QueryNodesByValueResponse, error) {
	treeQueryHandler := handler.NewTreeQueryHandler(s.config)
	return errors.WrapWithGRPCError(treeQueryHandler.QueryNodesByValue(ctx, req))
}
