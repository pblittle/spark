package watchtower

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/lightsparkdev/spark"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/so/ent"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	meter = otel.Meter("watchtower")

	// Metrics
	nodeTxBroadcastCounter   metric.Int64Counter
	refundTxBroadcastCounter metric.Int64Counter
)

func init() {
	var err error

	nodeTxBroadcastCounter, err = meter.Int64Counter(
		"watchtower.node_tx.broadcast_total",
		metric.WithDescription("Total number of node transactions broadcast by watchtower"),
	)
	if err != nil {
		slog.Error("Failed to create node tx broadcast counter", "error", err)
	}

	refundTxBroadcastCounter, err = meter.Int64Counter(
		"watchtower.refund_tx.broadcast_total",
		metric.WithDescription("Total number of refund transactions broadcast by watchtower"),
	)
	if err != nil {
		slog.Error("Failed to create refund tx broadcast counter", "error", err)
	}
}

type bitcoinClient interface {
	SendRawTransaction(tx *wire.MsgTx, allowHighFees bool) (*chainhash.Hash, error)
}

// BroadcastTransaction broadcasts a transaction to the network
func BroadcastTransaction(ctx context.Context, btcClient bitcoinClient, nodeID string, txBytes []byte) error {
	tx, err := common.TxFromRawTxBytes(txBytes)
	if err != nil {
		return fmt.Errorf("watchtower failed to parse transaction: %w", err)
	}
	// TODO: Broadcast Direct Refund TX.
	slog.InfoContext(ctx, "Attempting to broadcast transaction", "tx", tx)
	txHash, err := btcClient.SendRawTransaction(tx, false)
	if err != nil {
		if alreadyBroadcasted(err) {
			slog.InfoContext(ctx, "Transaction already in mempool", "node_id", nodeID)
			return nil
		}
		return fmt.Errorf("watchtower failed to broadcast transaction: %w", err)
	}

	toString := hex.EncodeToString(txHash[:])
	slog.InfoContext(ctx, "Successfully broadcast transaction", "tx_hash", toString)
	return nil
}

// alreadyBroadcast returns true if the given error indicates another SO has already broadcasted the tx.
func alreadyBroadcasted(err error) bool {
	var rpcErr *btcjson.RPCError

	return errors.As(err, &rpcErr) && rpcErr.Code == btcjson.ErrRPCVerifyAlreadyInChain
}

// CheckExpiredTimeLocks checks for TXs with expired time locks and broadcasts them if needed.
func CheckExpiredTimeLocks(ctx context.Context, bitcoinClient *rpcclient.Client, node *ent.TreeNode, blockHeight int64, network common.Network) error {
	if node.NodeConfirmationHeight == 0 {
		nodeTx, err := common.TxFromRawTxBytes(node.RawTx)
		if err != nil {
			return fmt.Errorf("watchtower failed to parse node tx: %w", err)
		}
		// Check if node TX has a timelock and has parent
		if nodeTx.TxIn[0].Sequence <= 0xFFFFFFFE {
			// Check if parent is confirmed and timelock has expired
			parent, err := node.QueryParent().Only(ctx)
			if err != nil {
				return fmt.Errorf("watchtower failed to query parent: %w", err)
			}
			if parent.NodeConfirmationHeight > 0 {
				timelockExpiryHeight := uint64(nodeTx.TxIn[0].Sequence&0xFFFF) + parent.NodeConfirmationHeight
				if timelockExpiryHeight+spark.WatchtowerTimeLockBuffer <= uint64(blockHeight) {
					if err := BroadcastTransaction(ctx, bitcoinClient, node.ID.String(), node.DirectTx); err != nil {
						// Record node tx broadcast failure
						if nodeTxBroadcastCounter != nil {
							nodeTxBroadcastCounter.Add(ctx, 1, metric.WithAttributes(
								attribute.String("network", network.String()),
								attribute.String("result", "failure"),
							))
						}
						slog.InfoContext(ctx, "Failed to broadcast node tx", "error", err)
						return fmt.Errorf("watchtower failed to broadcast node tx: %w", err)
					}

					// Record successful node tx broadcast
					if nodeTxBroadcastCounter != nil {
						nodeTxBroadcastCounter.Add(ctx, 1, metric.WithAttributes(
							attribute.String("network", network.String()),
							attribute.String("result", "success"),
						))
					}
				}
			}
		}
	} else if len(node.RawRefundTx) > 0 && node.RefundConfirmationHeight == 0 {
		refundTx, err := common.TxFromRawTxBytes(node.RawRefundTx)
		if err != nil {
			return fmt.Errorf("watchtower failed to parse refund tx: %w", err)
		}

		timelockExpiryHeight := uint64(refundTx.TxIn[0].Sequence&0xFFFF) + node.NodeConfirmationHeight
		if timelockExpiryHeight+spark.WatchtowerTimeLockBuffer <= uint64(blockHeight) {
			if err := BroadcastTransaction(ctx, bitcoinClient, node.ID.String(), node.DirectRefundTx); err != nil {
				// Try broadcasting the DirectFromCpfpRefundTx as a fallback
				if len(node.DirectFromCpfpRefundTx) > 0 {
					if err := BroadcastTransaction(ctx, bitcoinClient, node.ID.String(), node.DirectFromCpfpRefundTx); err != nil {
						// Record refund tx broadcast failure
						if refundTxBroadcastCounter != nil {
							refundTxBroadcastCounter.Add(ctx, 1, metric.WithAttributes(
								attribute.String("network", network.String()),
								attribute.String("result", "failure"),
							))
						}
						slog.InfoContext(ctx, "Failed to broadcast both direct refund tx and direct from cpfp refund tx", "error", err)
						return fmt.Errorf("watchtower failed to broadcast refund txs: %v", err)
					}
					// Record successful refund tx broadcast
					if refundTxBroadcastCounter != nil {
						refundTxBroadcastCounter.Add(ctx, 1, metric.WithAttributes(
							attribute.String("network", network.String()),
							attribute.String("result", "success"),
						))
					}
					return nil
				}
				// Record refund tx broadcast failure if no DirectFromCpfpRefundTx available
				if refundTxBroadcastCounter != nil {
					refundTxBroadcastCounter.Add(ctx, 1, metric.WithAttributes(
						attribute.String("network", network.String()),
						attribute.String("result", "failure"),
					))
				}
				slog.InfoContext(ctx, "Failed to broadcast direct refund tx", "error", err)
				return fmt.Errorf("watchtower failed to broadcast refund tx: %w", err)
			}

			// Record successful refund tx broadcast
			if refundTxBroadcastCounter != nil {
				refundTxBroadcastCounter.Add(ctx, 1, metric.WithAttributes(
					attribute.String("network", network.String()),
					attribute.String("result", "success"),
				))
			}
		}
	}

	return nil
}
