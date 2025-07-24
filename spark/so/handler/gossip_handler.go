package handler

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common/logging"
	pbgossip "github.com/lightsparkdev/spark/proto/gossip"
	pbinternal "github.com/lightsparkdev/spark/proto/spark_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	enttree "github.com/lightsparkdev/spark/so/ent/tree"
)

type GossipHandler struct {
	config *so.Config
}

func NewGossipHandler(config *so.Config) *GossipHandler {
	return &GossipHandler{config: config}
}

func (h *GossipHandler) HandleGossipMessage(ctx context.Context, gossipMessage *pbgossip.GossipMessage, forCoordinator bool) error {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Info("handling gossip message", "gossip_id", gossipMessage.MessageId)
	switch gossipMessage.Message.(type) {
	case *pbgossip.GossipMessage_CancelTransfer:
		cancelTransfer := gossipMessage.GetCancelTransfer()
		h.handleCancelTransferGossipMessage(ctx, cancelTransfer)
	case *pbgossip.GossipMessage_SettleSenderKeyTweak:
		settleSenderKeyTweak := gossipMessage.GetSettleSenderKeyTweak()
		h.handleSettleSenderKeyTweakGossipMessage(ctx, settleSenderKeyTweak, forCoordinator)
	case *pbgossip.GossipMessage_RollbackTransfer:
		rollbackTransfer := gossipMessage.GetRollbackTransfer()
		h.handleRollbackTransfer(ctx, rollbackTransfer)
	case *pbgossip.GossipMessage_MarkTreesExited:
		markTreesExited := gossipMessage.GetMarkTreesExited()
		h.handleMarkTreesExited(ctx, markTreesExited)
	case *pbgossip.GossipMessage_FinalizeTreeCreation:
		finalizeTreeCreation := gossipMessage.GetFinalizeTreeCreation()
		h.handleFinalizeTreeCreationGossipMessage(ctx, finalizeTreeCreation, forCoordinator)
	case *pbgossip.GossipMessage_FinalizeTransfer:
		finalizeTransfer := gossipMessage.GetFinalizeTransfer()
		h.handleFinalizeTransferGossipMessage(ctx, finalizeTransfer, forCoordinator)
	case *pbgossip.GossipMessage_FinalizeRefreshTimelock:
		finalizeRefreshTimelock := gossipMessage.GetFinalizeRefreshTimelock()
		h.handleFinalizeRefreshTimelockGossipMessage(ctx, finalizeRefreshTimelock, forCoordinator)
	case *pbgossip.GossipMessage_FinalizeExtendLeaf:
		finalizeExtendLeaf := gossipMessage.GetFinalizeExtendLeaf()
		h.handleFinalizeExtendLeafGossipMessage(ctx, finalizeExtendLeaf, forCoordinator)
	default:
		return fmt.Errorf("unsupported gossip message type: %T", gossipMessage.Message)
	}
	return nil
}

func (h *GossipHandler) handleCancelTransferGossipMessage(ctx context.Context, cancelTransfer *pbgossip.GossipMessageCancelTransfer) {
	transferHandler := NewBaseTransferHandler(h.config)
	err := transferHandler.CancelTransferInternal(ctx, cancelTransfer.TransferId)
	if err != nil {
		// If there's an error, it's still considered the message is delivered successfully.
		logger := logging.GetLoggerFromContext(ctx)
		logger.Error("failed to cancel transfer", "error", err, "transfer_id", cancelTransfer.TransferId)
	}
}

func (h *GossipHandler) handleSettleSenderKeyTweakGossipMessage(ctx context.Context, settleSenderKeyTweak *pbgossip.GossipMessageSettleSenderKeyTweak, forCoordinator bool) {
	transferHandler := NewBaseTransferHandler(h.config)
	_, err := transferHandler.CommitSenderKeyTweaks(ctx, settleSenderKeyTweak.TransferId, settleSenderKeyTweak.SenderKeyTweakProofs, forCoordinator)
	if err != nil {
		// If there's an error, it's still considered the message is delivered successfully.
		logger := logging.GetLoggerFromContext(ctx)
		logger.Error("failed to settle sender key tweak", "error", err, "transfer_id", settleSenderKeyTweak.TransferId)
	}
}

func (h *GossipHandler) handleRollbackTransfer(ctx context.Context, req *pbgossip.GossipMessageRollbackTransfer) {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Info("Handling rollback transfer gossip message", "transfer_id", req.TransferId)

	baseHandler := NewBaseTransferHandler(h.config)
	err := baseHandler.RollbackTransfer(ctx, req.TransferId)
	if err != nil {
		logger.Error("Failed to rollback transfer", "error", err, "transfer_id", req.TransferId)
	}
}

func (h *GossipHandler) handleMarkTreesExited(ctx context.Context, req *pbgossip.GossipMessageMarkTreesExited) {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Info("Handling mark trees exited gossip message", "tree_ids", req.TreeIds)

	treeIDs := make([]uuid.UUID, 0)
	for _, treeID := range req.TreeIds {
		treeUUID, err := uuid.Parse(treeID)
		if err != nil {
			logger.Error("Failed to parse tree ID", "error", err, "tree_id", treeID)
			continue
		}
		treeIDs = append(treeIDs, treeUUID)
	}

	db, err := ent.GetDbFromContext(ctx)
	if err != nil {
		logger.Error("Failed to get or create current tx for request", "error", err)
		return
	}

	trees, err := db.Tree.Query().
		Where(enttree.IDIn(treeIDs...)).
		ForUpdate().
		All(ctx)
	if err != nil {
		logger.Error("Failed to query trees", "error", err)
		return
	}

	treeExitHandler := NewTreeExitHandler(h.config)
	err = treeExitHandler.MarkTreesExited(ctx, trees)
	if err != nil {
		logger.Error("failed to mark trees exited", "error", err, "tree_ids", req.TreeIds)
	}
}

func (h *GossipHandler) handleFinalizeTreeCreationGossipMessage(ctx context.Context, finalizeNodeSignatures *pbgossip.GossipMessageFinalizeTreeCreation, forCoordinator bool) {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Info("Handling finalize tree creation gossip message")

	if forCoordinator {
		return
	}

	depositHandler := NewInternalDepositHandler(h.config)
	err := depositHandler.FinalizeTreeCreation(ctx, &pbinternal.FinalizeTreeCreationRequest{Nodes: finalizeNodeSignatures.InternalNodes, Network: finalizeNodeSignatures.ProtoNetwork})
	if err != nil {
		logger.Error("Failed to finalize tree creation", "error", err)
	}
}

func (h *GossipHandler) handleFinalizeTransferGossipMessage(ctx context.Context, finalizeNodeSignatures *pbgossip.GossipMessageFinalizeTransfer, forCoordinator bool) {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Info("Handling finalize transfer gossip message")

	if forCoordinator {
		return
	}
	transferHandler := NewInternalTransferHandler(h.config)
	err := transferHandler.FinalizeTransfer(ctx, &pbinternal.FinalizeTransferRequest{TransferId: finalizeNodeSignatures.TransferId, Nodes: finalizeNodeSignatures.InternalNodes, Timestamp: finalizeNodeSignatures.CompletionTimestamp})
	if err != nil {
		logger.Error("Failed to finalize transfer", "error", err)
	}
}

func (h *GossipHandler) handleFinalizeRefreshTimelockGossipMessage(ctx context.Context, finalizeNodeSignatures *pbgossip.GossipMessageFinalizeRefreshTimelock, forCoordinator bool) {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Info("Handling finalize refresh timelock gossip message")

	if forCoordinator {
		return
	}

	refreshTimelockHandler := NewInternalRefreshTimelockHandler(h.config)
	err := refreshTimelockHandler.FinalizeRefreshTimelock(ctx, &pbinternal.FinalizeRefreshTimelockRequest{Nodes: finalizeNodeSignatures.InternalNodes})
	if err != nil {
		logger.Error("Failed to finalize refresh timelock", "error", err)
	}
}

func (h *GossipHandler) handleFinalizeExtendLeafGossipMessage(ctx context.Context, finalizeNodeSignatures *pbgossip.GossipMessageFinalizeExtendLeaf, forCoordinator bool) {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Info("Handling finalize extend leaf gossip message")

	if forCoordinator {
		return
	}
	extendLeafHandler := NewInternalExtendLeafHandler(h.config)
	err := extendLeafHandler.FinalizeExtendLeaf(ctx, &pbinternal.FinalizeExtendLeafRequest{Node: finalizeNodeSignatures.InternalNodes[0]})
	if err != nil {
		logger.Error("Failed to finalize extend leaf", "error", err)
	}
}
