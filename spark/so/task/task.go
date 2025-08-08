package task

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"time"

	"github.com/lightsparkdev/spark"
	"github.com/lightsparkdev/spark/common/keys"

	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/handler/signing_handler"
	"github.com/lightsparkdev/spark/so/handler/tokens"
	"github.com/lightsparkdev/spark/so/helper"
	"github.com/lightsparkdev/spark/so/objects"
	"google.golang.org/protobuf/types/known/timestamppb"

	"entgo.io/ent/dialect/sql"
	"github.com/go-co-op/gocron/v2"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/logging"
	pbspark "github.com/lightsparkdev/spark/proto/spark"
	pbinternal "github.com/lightsparkdev/spark/proto/spark_internal"
	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"
	tokeninternalpb "github.com/lightsparkdev/spark/proto/spark_token_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/ent/gossip"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/signingcommitment"
	"github.com/lightsparkdev/spark/so/ent/tokenfreeze"
	"github.com/lightsparkdev/spark/so/ent/tokenoutput"
	"github.com/lightsparkdev/spark/so/ent/tokentransaction"
	"github.com/lightsparkdev/spark/so/ent/transfer"
	"github.com/lightsparkdev/spark/so/ent/tree"
	"github.com/lightsparkdev/spark/so/ent/treenode"
	"github.com/lightsparkdev/spark/so/ent/utxoswap"
	"github.com/lightsparkdev/spark/so/handler"
)

var (
	defaultTaskTimeout              = 1 * time.Minute
	dkgTaskTimeout                  = 3 * time.Minute
	deleteStaleTreeNodesTaskTimeout = 10 * time.Minute
)

// BaseTask contains common fields for all task types.

type Task func(context.Context, *so.Config) error

// BaseTaskSpec is a task that is scheduled to run.
type BaseTaskSpec struct { //nolint:revive
	// Name is the human-readable name of the task.
	Name string
	// Timeout is the maximum time the task is allowed to run before it will be cancelled.
	Timeout *time.Duration
	// Whether to run the task in the hermetic test environment.
	RunInTestEnv bool
	// If true, the task will not run
	Disabled bool
	// Task is the function that is run when the task is scheduled.
	Task func(context.Context, *so.Config) error
}

// ScheduledTask is a task that runs on a schedule.
type ScheduledTaskSpec struct {
	BaseTaskSpec
	// ExecutionInterval is the interval between each run of the task.
	ExecutionInterval time.Duration
}

// StartupTask is a task that runs once at startup.
type StartupTaskSpec struct {
	BaseTaskSpec
	// RetryInterval is the interval between retries for startup tasks. If nil, no retries are performed.
	// Retries may be necessary if a startup task is dependent on other asynchronous setup, such as internal
	// GRPCs to other operators that may not be ready immediately upon the startup of this operator.
	RetryInterval *time.Duration
}

// AllScheduledTasks returns all the tasks that are scheduled to run.
func AllScheduledTasks() []ScheduledTaskSpec {
	return []ScheduledTaskSpec{
		{
			ExecutionInterval: 10 * time.Second,
			BaseTaskSpec: BaseTaskSpec{
				Name:         "dkg",
				Timeout:      &dkgTaskTimeout,
				RunInTestEnv: true,
				Task: func(ctx context.Context, config *so.Config) error {
					return ent.RunDKGIfNeeded(ctx, config)
				},
			},
		},
		{
			ExecutionInterval: 1 * time.Minute,
			BaseTaskSpec: BaseTaskSpec{
				Name:         "generate_signing_commitments",
				RunInTestEnv: false,
				Task: func(ctx context.Context, config *so.Config) error {
					db, err := ent.GetDbFromContext(ctx)
					if err != nil {
						return fmt.Errorf("failed to get or create current tx for request: %w", err)
					}

					logger := logging.GetLoggerFromContext(ctx)
					entCommitments := make([]*ent.SigningCommitmentCreate, 0)
					for _, operator := range config.SigningOperatorMap {
						count, err := db.SigningCommitment.Query().Where(
							signingcommitment.OperatorIndexEQ(uint(operator.ID)),
							signingcommitment.StatusEQ(st.SigningCommitmentStatusAvailable),
						).Count(ctx)
						if err != nil {
							logger.Error("failed to query signing commitments for operator", "operator", operator.ID, "error", err)
							continue
						}

						if count < spark.SigningCommitmentReserve {
							var resp *pbinternal.FrostRound1Response
							if operator.ID == config.Index {
								signingHandler := signing_handler.NewFrostSigningHandler(config)
								resp, err = signingHandler.GenerateRandomNonces(ctx, spark.SigningCommitmentBatchSize)
								if err != nil {
									return err
								}
							}

							conn, err := operator.NewGRPCConnection()
							if err != nil {
								return err
							}

							client := pbinternal.NewSparkInternalServiceClient(conn)
							resp, err = client.FrostRound1(ctx, &pbinternal.FrostRound1Request{
								RandomNonceCount: spark.SigningCommitmentBatchSize,
							})
							if err != nil {
								logger.Error("failed to generate signing commitments for operator", "operator", operator.ID, "error", err)
								continue
							}

							for _, pbCommitment := range resp.SigningCommitments {
								commitments := objects.SigningCommitment{}
								err := commitments.UnmarshalProto(pbCommitment)
								if err != nil {
									return err
								}

								commitmentBinary := commitments.MarshalBinary()
								if err != nil {
									return err
								}

								entCommitments = append(
									entCommitments,
									db.SigningCommitment.Create().
										SetOperatorIndex(uint(operator.ID)).
										SetStatus(st.SigningCommitmentStatusAvailable).
										SetNonceCommitment(commitmentBinary),
								)
							}
						}
					}

					if err := db.SigningCommitment.CreateBulk(entCommitments...).Exec(ctx); err != nil {
						return err
					}

					return nil
				},
			},
		},
		{
			ExecutionInterval: 1 * time.Minute,
			BaseTaskSpec: BaseTaskSpec{
				Name:         "cancel_expired_transfers",
				RunInTestEnv: true,
				Task: func(ctx context.Context, config *so.Config) error {
					logger := logging.GetLoggerFromContext(ctx)
					h := handler.NewTransferHandler(config)

					tx, err := ent.GetDbFromContext(ctx)
					if err != nil {
						return fmt.Errorf("failed to get or create current tx for request: %w", err)
					}
					query := tx.Transfer.Query().Where(
						transfer.And(
							transfer.Or(
								transfer.StatusEQ(st.TransferStatusSenderInitiated),
								transfer.And(
									transfer.StatusEQ(st.TransferStatusSenderKeyTweakPending),
									transfer.TypeEQ(st.TransferTypePreimageSwap),
								),
							),
							transfer.ExpiryTimeLT(time.Now()),
							transfer.ExpiryTimeNEQ(time.Unix(0, 0)),
							transfer.TypeNEQ(st.TransferTypeCooperativeExit),
						),
					)

					transfers, err := query.All(ctx)
					if err != nil {
						return err
					}

					for _, dbTransfer := range transfers {
						err := h.CancelTransferInternal(ctx, dbTransfer.ID.String())
						if err != nil {
							logger.Error("failed to cancel transfer", "error", err)
						}
					}

					return nil
				},
			},
		},
		{
			ExecutionInterval: 1 * time.Hour,
			BaseTaskSpec: BaseTaskSpec{
				Name:         "delete_stale_pending_trees",
				Timeout:      &deleteStaleTreeNodesTaskTimeout,
				RunInTestEnv: false,
				// TODO(LIG-7896): This task keeps on getting stuck on
				// very large trees. Disabling for now as we investigate
				Disabled: true,
				Task: func(ctx context.Context, _ *so.Config) error {
					logger := logging.GetLoggerFromContext(ctx)
					tx, err := ent.GetDbFromContext(ctx)
					if err != nil {
						return fmt.Errorf("failed to get or create current tx for request: %w", err)
					}

					// Find tree nodes that are:
					// 1. Older than 5 days
					// 2. Have status "CREATING"
					// 3. Belong to trees with status "PENDING"
					query := tx.TreeNode.Query().Where(
						treenode.And(
							treenode.StatusEQ(st.TreeNodeStatusCreating),
							treenode.CreateTimeLTE(time.Now().Add(-5*24*time.Hour)),
							treenode.HasTreeWith(tree.StatusEQ(st.TreeStatusPending)),
						),
					).WithTree()

					treeNodes, err := query.All(ctx)
					if err != nil {
						logger.Error("failed to query tree nodes", "error", err)
						return err
					}

					if len(treeNodes) == 0 {
						logger.Info("Found no stale tree nodes.")
						return nil
					}

					treeToTreeNodes := make(map[uuid.UUID][]uuid.UUID)
					for _, node := range treeNodes {
						treeID := node.Edges.Tree.ID
						treeToTreeNodes[treeID] = append(treeToTreeNodes[treeID], node.ID)
					}

					for treeID, treeNodeIDs := range treeToTreeNodes {
						logger.Info(fmt.Sprintf("Deleting stale tree %s along with associated tree nodes (%d in total).", treeID, len(treeNodeIDs)))

						numDeleted, err := tx.TreeNode.Delete().Where(treenode.IDIn(treeNodeIDs...)).Exec(ctx)
						if err != nil {
							logger.Error("failed to delete tree nodes", "tree_id", treeID, "error", err)
							return err
						}

						logger.Info(fmt.Sprintf("Deleted %d tree nodes.", numDeleted))

						// Delete the associated trees
						_, err = tx.Tree.Delete().Where(tree.IDEQ(treeID)).Exec(ctx)
						if err != nil {
							logger.Error("failed to delete tree", "tree_id", treeID, "error", err)
							return err
						}

						logger.Info(fmt.Sprintf("Deleted tree %s.", treeID))
					}

					return nil
				},
			},
		},
		{
			ExecutionInterval: 5 * time.Minute,
			BaseTaskSpec: BaseTaskSpec{
				Name: "resume_send_transfer",
				Task: func(ctx context.Context, config *so.Config) error {
					logger := logging.GetLoggerFromContext(ctx)
					h := handler.NewTransferHandler(config)

					tx, err := ent.GetDbFromContext(ctx)
					if err != nil {
						return fmt.Errorf("failed to get or create current tx for request: %w", err)
					}
					query := tx.Transfer.Query().Where(
						transfer.And(
							transfer.StatusEQ(st.TransferStatusSenderInitiatedCoordinator),
							transfer.TypeNotIn(st.TransferTypeCooperativeExit, st.TransferTypePreimageSwap),
						),
					).Limit(1000)

					transfers, err := query.All(ctx)
					if err != nil {
						return err
					}

					for _, dbTransfer := range transfers {
						err := h.ResumeSendTransfer(ctx, dbTransfer)
						if err != nil {
							logger.Error("failed to resume send transfer", "error", err)
						}
					}
					return nil
				},
			},
		},
		{
			ExecutionInterval: 1 * time.Hour,
			BaseTaskSpec: BaseTaskSpec{
				Name:         "cancel_or_finalize_expired_token_transactions",
				RunInTestEnv: true,
				Task: func(ctx context.Context, config *so.Config) error {
					logger := logging.GetLoggerFromContext(ctx)
					currentTime := time.Now()

					h := tokens.NewInternalFinalizeTokenHandler(config)
					logger.Info("Checking for expired token transactions",
						"current_time", currentTime.Format(time.RFC3339))
					// TODO: Consider adding support for expiring mints as well (although not strictly needed
					// because mints do not lock TTXOs).
					tx, err := ent.GetDbFromContext(ctx)
					if err != nil {
						return fmt.Errorf("failed to get or create current tx for request: %w", err)
					}
					// Use mainnet value for simplicity because expiry duration is the same on all networks
					expiryDuration := config.Lrc20Configs[string(st.NetworkMainnet)].TransactionExpiryDuration
					expiredTransfersQuery := tx.TokenTransaction.
						Query().
						ForUpdate().
						WithCreatedOutput().
						WithSpentOutput(func(q *ent.TokenOutputQuery) {
							// Needed to enable marshalling of the token transaction proto.
							q.WithOutputCreatedTokenTransaction()
						}).Where(
						tokentransaction.And(
							// Transfer transactions are effectively pending in either STARTED or SIGNED state.
							// Note that different SOs may have different states if SIGNED calls did not succeed with all SOs.
							// We only check for expired v0 transactions here, which is defined as a transaction in one
							// of these states that was created more than 180 seconds ago.
							tokentransaction.StatusIn(st.TokenTransactionStatusStarted, st.TokenTransactionStatusSigned),
							tokentransaction.Not(tokentransaction.HasMint()),
							tokentransaction.Not(tokentransaction.HasCreate()),
							tokentransaction.VersionEQ(0),
							tokentransaction.CreateTimeLT(currentTime.Add(-expiryDuration)),
						),
					)
					expiredTransferTransactions, err := expiredTransfersQuery.All(ctx)
					if err != nil {
						logger.Error(fmt.Sprintf("Failed to query expired transfer token transactions: %v", err))
					}
					logger.Info(fmt.Sprintf("Expired token transactions query completed, found %d expired transfers", len(expiredTransferTransactions)))

					for _, expiredTransaction := range expiredTransferTransactions {
						txFinalHash := hex.EncodeToString(expiredTransaction.FinalizedTokenTransactionHash)
						expiryTime := expiredTransaction.ExpiryTime.Format(time.RFC3339)

						logger.Info(fmt.Sprintf("Attempting to cancel or finalize expired token transaction: id=%s, hash=%s, expiry=%s, status=%s",
							expiredTransaction.ID,
							txFinalHash,
							expiryTime,
							expiredTransaction.Status))

						err = h.CancelOrFinalizeExpiredTokenTransaction(ctx, config, expiredTransaction)
						if err != nil {
							logger.Error(fmt.Sprintf("Failed to cancel or finalize expired token transaction: id=%s, hash=%s, error=%v",
								expiredTransaction.ID,
								txFinalHash,
								err))
						} else {
							logger.Info(fmt.Sprintf("Successfully cancelled or finalized expired token transaction: id=%s, hash=%s",
								expiredTransaction.ID,
								txFinalHash))
						}
					}
					return nil
				},
			},
		},
		{
			ExecutionInterval: 10 * time.Minute,
			BaseTaskSpec: BaseTaskSpec{
				Name:         "finalize_revealed_token_transactions",
				RunInTestEnv: true,
				Task: func(ctx context.Context, config *so.Config) error {
					logger := logging.GetLoggerFromContext(ctx)
					logger.Info("[cron] Finalizing revealed token transactions")
					db, err := ent.GetDbFromContext(ctx)
					if err != nil {
						return fmt.Errorf("failed to get or create current tx for request: %w", err)
					}
					tokenTransactions, err := db.TokenTransaction.Query().
						Where(
							tokentransaction.And(
								tokentransaction.StatusEQ(st.TokenTransactionStatusRevealed),
							),
						).
						WithPeerSignatures().
						WithSpentOutput(func(q *ent.TokenOutputQuery) {
							q.WithOutputCreatedTokenTransaction()
						}).
						WithCreatedOutput().
						All(ctx)
					if err != nil {
						return err
					}
					logger.Info(fmt.Sprintf("[cron] Found %d token transactions to finalize", len(tokenTransactions)))
					for _, tokenTransaction := range tokenTransactions {
						var spentOutputs []*tokenpb.TokenOutputToSpend
						var createdOutputs []*tokenpb.TokenOutput
						signaturesPackage := make(map[string]*tokeninternalpb.SignTokenTransactionFromCoordinationResponse)

						if tokenTransaction.Edges.SpentOutput != nil {
							for _, spentOutput := range tokenTransaction.Edges.SpentOutput {
								spentOutputs = append(spentOutputs, &tokenpb.TokenOutputToSpend{
									PrevTokenTransactionHash: spentOutput.Edges.OutputCreatedTokenTransaction.FinalizedTokenTransactionHash,
									PrevTokenTransactionVout: uint32(spentOutput.CreatedTransactionOutputVout),
								})
							}
						}
						if tokenTransaction.Edges.CreatedOutput != nil {
							for _, createdOutput := range tokenTransaction.Edges.CreatedOutput {
								idStr := createdOutput.ID.String()
								createdOutputs = append(createdOutputs, &tokenpb.TokenOutput{
									Id:                            &idStr,
									OwnerPublicKey:                createdOutput.OwnerPublicKey,
									RevocationCommitment:          createdOutput.WithdrawRevocationCommitment,
									WithdrawBondSats:              &createdOutput.WithdrawBondSats,
									WithdrawRelativeBlockLocktime: &createdOutput.WithdrawRelativeBlockLocktime,
									TokenPublicKey:                createdOutput.TokenPublicKey,
									TokenIdentifier:               createdOutput.TokenIdentifier,
									TokenAmount:                   createdOutput.TokenAmount,
								})
							}
						}

						var protoNetwork pbspark.Network
						if tokenTransaction.Edges.CreatedOutput != nil && len(tokenTransaction.Edges.CreatedOutput) > 0 {
							protoNetwork, err = common.ProtoNetworkFromSchemaNetwork(tokenTransaction.Edges.CreatedOutput[0].Network)
							if err != nil {
								return fmt.Errorf("unable to get proto network: %w", err)
							}
						} else {
							return fmt.Errorf("no created outputs found for token transaction: %s", tokenTransaction.ID)
						}

						if tokenTransaction.Edges.PeerSignatures != nil {
							for _, signature := range tokenTransaction.Edges.PeerSignatures {
								pubKey, err := keys.ParsePublicKey(signature.OperatorIdentityPublicKey)
								if err != nil {
									return fmt.Errorf("unable to parse public key: %w", err)
								}
								identifier := config.GetOperatorIdentifierFromIdentityPublicKey(pubKey)
								signaturesPackage[identifier] = &tokeninternalpb.SignTokenTransactionFromCoordinationResponse{
									SparkOperatorSignature: signature.Signature,
								}
							}
						}
						if tokenTransaction.OperatorSignature != nil {
							signaturesPackage[config.Identifier] = &tokeninternalpb.SignTokenTransactionFromCoordinationResponse{
								SparkOperatorSignature: tokenTransaction.OperatorSignature,
							}
						}

						tokenPb := &tokenpb.TokenTransaction{
							Version: uint32(tokenTransaction.Version),
							TokenInputs: &tokenpb.TokenTransaction_TransferInput{
								TransferInput: &tokenpb.TokenTransferInput{
									OutputsToSpend: spentOutputs,
								},
							},
							TokenOutputs: createdOutputs,
							ExpiryTime:   timestamppb.New(tokenTransaction.ExpiryTime),
							Network:      protoNetwork,
						}
						logger.Info("[cron] Finalizing token transaction",
							"num_signatures", len(signaturesPackage),
							"operator_ids", maps.Keys(signaturesPackage),
							"tx_hash", hex.EncodeToString(tokenTransaction.FinalizedTokenTransactionHash))
						signTokenHandler := tokens.NewSignTokenHandler(config)
						commitTransactionResponse, err := signTokenHandler.ExchangeRevocationSecretsAndFinalizeIfPossible(ctx, tokenPb, signaturesPackage, tokenTransaction.FinalizedTokenTransactionHash)
						if err != nil {
							return fmt.Errorf("cron job failed to exchange revocation secrets and finalize if possible for token txHash: %x: %w", tokenTransaction.FinalizedTokenTransactionHash, err)
						} else {
							logger.Info(fmt.Sprintf("Successfully exchanged revocation secrets and finalized if possible for token txHash: %x. Commit response: %v", tokenTransaction.FinalizedTokenTransactionHash, commitTransactionResponse))
						}
					}
					return nil
				},
			},
		},
		{
			ExecutionInterval: 5 * time.Minute,
			BaseTaskSpec: BaseTaskSpec{
				Name:         "send_gossip",
				RunInTestEnv: true,
				Task: func(ctx context.Context, config *so.Config) error {
					logger := logging.GetLoggerFromContext(ctx)
					gossipHandler := handler.NewSendGossipHandler(config)
					tx, err := ent.GetDbFromContext(ctx)
					if err != nil {
						return fmt.Errorf("failed to get or create current tx for request: %w", err)
					}
					query := tx.Gossip.Query().Where(gossip.StatusEQ(st.GossipStatusPending)).Limit(1000)
					gossips, err := query.ForUpdate().All(ctx)
					if err != nil {
						return err
					}

					for _, gossipMsg := range gossips {
						_, err := gossipHandler.SendGossipMessage(ctx, gossipMsg)
						if err != nil {
							logger.Error("failed to send gossip", "error", err)
						}
					}
					return nil
				},
			},
		},
		{
			ExecutionInterval: 1 * time.Minute,
			BaseTaskSpec: BaseTaskSpec{
				Name:         "complete_utxo_swap",
				RunInTestEnv: true,
				Task: func(ctx context.Context, config *so.Config) error {
					logger := logging.GetLoggerFromContext(ctx)
					tx, err := ent.GetDbFromContext(ctx)
					if err != nil {
						return fmt.Errorf("failed to get or create current tx for request: %w", err)
					}

					query := tx.UtxoSwap.Query().
						Where(utxoswap.StatusEQ(st.UtxoSwapStatusCreated)).
						Where(utxoswap.CoordinatorIdentityPublicKeyEQ(config.IdentityPublicKey().Serialize())).
						Order(utxoswap.ByCreateTime(sql.OrderDesc())).
						Limit(100)

					utxoSwaps, err := query.All(ctx)
					if err != nil {
						return err
					}

					for _, utxoSwap := range utxoSwaps {
						dbTransfer, err := utxoSwap.QueryTransfer().Only(ctx)
						if err != nil && !ent.IsNotFound(err) {
							logger.Error("failed to get transfer for a utxo swap", "error", err)
							continue
						}
						if dbTransfer == nil && utxoSwap.RequestType != st.UtxoSwapRequestTypeRefund {
							logger.Debug("No transfer found for a non-refund utxo swap", "utxo_swap_id", utxoSwap.ID)
							continue
						}
						if utxoSwap.RequestType == st.UtxoSwapRequestTypeRefund || dbTransfer.Status == st.TransferStatusCompleted {
							logger.Debug("Marking utxo swap as completed", "utxo_swap_id", utxoSwap.ID)

							utxo, err := utxoSwap.QueryUtxo().Only(ctx)
							if err != nil {
								return fmt.Errorf("unable to get utxo: %w", err)
							}
							protoNetwork, err := common.ProtoNetworkFromSchemaNetwork(utxo.Network)
							if err != nil {
								return fmt.Errorf("unable to get proto network: %w", err)
							}
							protoUtxo := &pbspark.UTXO{
								Txid:    utxo.Txid,
								Vout:    utxo.Vout,
								Network: protoNetwork,
							}

							completedUtxoSwapRequest, err := handler.CreateCompleteSwapForUtxoRequest(config, protoUtxo)
							if err != nil {
								logger.Warn("Failed to get complete swap for utxo request, cron task to retry", "error", err)
							} else {
								h := handler.NewInternalDepositHandler(config)
								if err := h.CompleteSwapForAllOperators(ctx, config, completedUtxoSwapRequest); err != nil {
									logger.Warn("Failed to mark a utxo swap as completed in all operators, cron task to retry", "error", err)
								}
							}
						}
					}
					return nil
				},
			},
		},
	}
}

func AllStartupTasks() []StartupTaskSpec {
	entityDkgTaskTimeout := 5 * time.Minute
	entityDkgRetryInterval := 10 * time.Second
	backfillTokenOutputInterval := 10 * time.Minute

	return []StartupTaskSpec{
		{
			RetryInterval: &entityDkgRetryInterval,
			BaseTaskSpec: BaseTaskSpec{
				Name:         "maybe_reserve_entity_dkg",
				RunInTestEnv: true,
				Timeout:      &entityDkgTaskTimeout,
				Task: func(ctx context.Context, config *so.Config) error {
					logger := logging.GetLoggerFromContext(ctx)
					tx, err := ent.GetDbFromContext(ctx)
					if err != nil {
						return fmt.Errorf("failed to get or create current tx for request: %w", err)
					}
					if config.Index != 0 {
						logger.Info("Not the first operator, skipping entity DKG reservation task")
						return nil
					}

					// Try to find existing entity DKG key
					entityDkgKey, err := tx.EntityDkgKey.Query().
						WithSigningKeyshare().
						Only(ctx)

					var keyshare *ent.SigningKeyshare
					if err != nil {
						if !ent.IsNotFound(err) {
							return fmt.Errorf("failed to query for entity DKG key: %w", err)
						}
						// No existing entity DKG key found, create a new one
						keyshares, err := ent.GetUnusedSigningKeysharesTx(ctx, tx, config, 1)
						if err != nil {
							return fmt.Errorf("failed to get unused signing keyshares: %w", err)
						}
						if len(keyshares) == 0 {
							return fmt.Errorf("no signing keyshares available yet")
						}

						keyshare = keyshares[0]
						_, err = tx.EntityDkgKey.Create().
							SetSigningKeyshareID(keyshare.ID).
							Save(ctx)
						if err != nil {
							return fmt.Errorf("failed to create entity DKG key: %w", err)
						}

						// Commit the existing transaction before making the operator calls to ensure it is not rolled back if they fail
						// due to the SOs still starting up.
						if err = tx.Commit(); err != nil {
							return fmt.Errorf("failed to commit entity DKG key: %w", err)
						}
					} else {
						// Existing entity DKG key found, get its signing keyshare
						keyshare, err = entityDkgKey.Edges.SigningKeyshareOrErr()
						if err != nil {
							return fmt.Errorf("failed to get signing keyshare from entity DKG key: %w", err)
						}
					}
					logger.Info("Found available signing keyshare, proceeding with reservation on other SOs", "keyshare_id", keyshare.ID)
					selection := helper.OperatorSelection{Option: helper.OperatorSelectionOptionExcludeSelf}
					_, err = helper.ExecuteTaskWithAllOperators(ctx, config, &selection, func(ctx context.Context, operator *so.SigningOperator) (any, error) {
						conn, err := operator.NewGRPCConnection()
						if err != nil {
							return nil, err
						}
						defer conn.Close()

						client := pbinternal.NewSparkInternalServiceClient(conn)
						_, err = client.ReserveEntityDkgKey(ctx, &pbinternal.ReserveEntityDkgKeyRequest{KeyshareId: keyshare.ID.String()})
						return nil, err
					})
					if err != nil {
						return fmt.Errorf("failed to reserve entity DKG key with operators. This is likely due to not all SOs being ready yet. Will retry in %s: %w", entityDkgRetryInterval, err)
					}

					logger.Info("Successfully verified reserved entity DKG key in all operators", "keyshare_id", keyshare.ID)
					return nil
				},
			},
		},
		{
			BaseTaskSpec: BaseTaskSpec{
				Name:         "backfill_token_freezes_token_identifier",
				RunInTestEnv: true,
				Task: func(ctx context.Context, config *so.Config) error {
					logger := logging.GetLoggerFromContext(ctx)
					logger.Info("Backfilling token create created_at")

					if !config.Token.EnableBackfillTokenFreezesTokenIdentifierTask {
						logger.Info("Backfill token output token identifiers and token create edges is disabled, skipping")
						return nil
					}

					tx, err := ent.GetDbFromContext(ctx)
					if err != nil {
						return fmt.Errorf("failed to get or create current tx for request: %w", err)
					}

					tokenFreezes, err := tx.TokenFreeze.Query().
						All(ctx)
					if err != nil {
						return fmt.Errorf("failed to get token freezes: %w", err)
					}
					logger.Info("Processing token freezes for backfill", "count", len(tokenFreezes))
					tokenCreatesByIssuerPubKey := make(map[string]*ent.TokenCreate)
					tokenCreates, err := tx.TokenCreate.Query().All(ctx)
					if err != nil {
						return fmt.Errorf("failed to get token creates: %w", err)
					}

					for _, tokenCreate := range tokenCreates {
						tokenCreatesByIssuerPubKey[string(tokenCreate.IssuerPublicKey)] = tokenCreate
					}

					var updatedCount int
					for _, tokenFreeze := range tokenFreezes {
						if tokenFreeze.TokenCreateID != uuid.Nil {
							continue
						}

						if len(tokenFreeze.TokenPublicKey) == 0 {
							logger.Warn("TokenFreeze has no token_public_key", "freeze_id", tokenFreeze.ID)
							continue
						}

						tokenCreate, exists := tokenCreatesByIssuerPubKey[string(tokenFreeze.TokenPublicKey)]
						if !exists {
							logger.Warn("No matching TokenCreate found for TokenFreeze",
								"freeze_id", tokenFreeze.ID,
								"token_public_key_len", len(tokenFreeze.TokenPublicKey))
							continue
						}
						_, err := tx.TokenFreeze.Update().
							Where(tokenfreeze.IDEQ(tokenFreeze.ID)).
							SetTokenCreateID(tokenCreate.ID).
							Save(ctx)
						if err != nil {
							return fmt.Errorf("failed to update token freeze %s with token identifier: %w",
								tokenFreeze.ID, err)
						}

						updatedCount++
						logger.Debug("Updated TokenFreeze with token identifier",
							"freeze_id", tokenFreeze.ID,
							"token_create_id", tokenCreate.ID)
					}

					logger.Info("Successfully backfilled token freezes with token identifiers",
						"updated_count", updatedCount,
						"total_freezes", len(tokenFreezes))

					return nil
				},
			},
		},
		{
			RetryInterval: &backfillTokenOutputInterval,
			BaseTaskSpec: BaseTaskSpec{
				Name:         "backfill_token_output_token_identifiers_and_token_create_edges",
				RunInTestEnv: true,
				Task: func(ctx context.Context, config *so.Config) error {
					logger := logging.GetLoggerFromContext(ctx)

					if !config.Token.EnableBackfillTokenOutputTask {
						logger.Info("Backfill token output token identifiers and token create edges is disabled, skipping")
						return nil
					}

					tx, err := ent.GetDbFromContext(ctx)
					if err != nil {
						return fmt.Errorf("failed to get or create current tx for request: %w", err)
					}

					createsByIssuerPubKey := make(map[string]*ent.TokenCreate)
					tokenCreates, err := tx.TokenCreate.Query().All(ctx)
					if err != nil {
						return fmt.Errorf("failed to get token creates: %w", err)
					}
					for _, tokenCreate := range tokenCreates {
						createsByIssuerPubKey[string(tokenCreate.IssuerPublicKey)] = tokenCreate
					}

					const pageLimit = 1000
					var lastID uuid.UUID
					for {
						tokenOutputsQuery := tx.TokenOutput.
							Query().
							Where(
								tokenoutput.CreateTimeGT(time.Date(2025, time.April, 28, 0, 0, 0, 0, time.UTC)),
							).
							Order(tokenoutput.ByID()).
							Limit(pageLimit)

						if lastID != uuid.Nil {
							tokenOutputsQuery = tokenOutputsQuery.Where(tokenoutput.IDGT(lastID))
						}

						tokenOutputsToBackfill, err := tokenOutputsQuery.All(ctx)
						if err != nil {
							return fmt.Errorf("failed to get token outputs to backfill: %w", err)
						}
						if len(tokenOutputsToBackfill) == 0 {
							// Once there are no more token outputs to backfill, break out of the loop.
							break
						}

						lastID = tokenOutputsToBackfill[len(tokenOutputsToBackfill)-1].ID

						tokenOutputIDByIssuerPubKeyStr := make(map[string][]uuid.UUID)
						for _, tokenOutput := range tokenOutputsToBackfill {
							tokenOutputIDByIssuerPubKeyStr[string(tokenOutput.TokenPublicKey)] = append(tokenOutputIDByIssuerPubKeyStr[string(tokenOutput.TokenPublicKey)], tokenOutput.ID)
						}

						for issuerPubKeyStr, tokenOutputIDs := range tokenOutputIDByIssuerPubKeyStr {
							if createsByIssuerPubKey[issuerPubKeyStr] == nil {
								logger.Warn("No token create found for issuer public key", "issuer_public_key", issuerPubKeyStr)
								continue
							}
							if _, err := tx.TokenOutput.Update().
								Where(tokenoutput.IDIn(tokenOutputIDs...)).
								SetTokenIdentifier(createsByIssuerPubKey[issuerPubKeyStr].TokenIdentifier).
								SetTokenCreateID(createsByIssuerPubKey[issuerPubKeyStr].ID).
								Save(ctx); err != nil {
								return fmt.Errorf("failed to update token outputs: %w", err)
							}
						}
					}
					logger.Info("Successfully backfilled token_ouputs with token_create and token_identifier")
					return nil
				},
			},
		},
		{
			RetryInterval: &backfillTokenOutputInterval,
			BaseTaskSpec: BaseTaskSpec{
				Name:         "delete_legacy_token_output_data",
				RunInTestEnv: true,
				Task: func(ctx context.Context, config *so.Config) error {
					logger := logging.GetLoggerFromContext(ctx)

					if !config.Token.EnableDeleteLegacyTokenOutputDataTask {
						logger.Info("Delete legacy token output data is disabled, skipping")
						return nil
					}

					tx, err := ent.GetDbFromContext(ctx)
					if err != nil {
						return fmt.Errorf("failed to get or create current tx for request: %w", err)
					}

					deletedTokenFreezes, err := tx.TokenFreeze.Delete().
						Where(tokenfreeze.TokenCreateIDIsNil()).
						Exec(ctx)
					if err != nil {
						return fmt.Errorf("failed to delete token freezes: %w", err)
					}
					logger.Info("Deleted token freezes", "count", deletedTokenFreezes)

					tokenOutputs, err := tx.TokenOutput.Query().
						Where(
							tokenoutput.And(
								tokenoutput.CreateTimeLT(time.Date(2025, time.April, 28, 0, 0, 0, 0, time.UTC)),
								tokenoutput.TokenIdentifierIsNil(),
							),
						).
						WithOutputCreatedTokenTransaction().
						WithOutputSpentTokenTransaction().
						All(ctx)
					if err != nil {
						return fmt.Errorf("failed to get token outputs: %w", err)
					}

					if len(tokenOutputs) == 0 {
						logger.Info("No legacy token outputs found, task complete")
						return nil
					}
					logger.Info("Found legacy token outputs to delete", "count", len(tokenOutputs))

					var (
						tokenTransactionIDs []uuid.UUID
						tokenOutputIDs      []uuid.UUID
					)

					transactionIDSet := make(map[uuid.UUID]struct{})

					for _, output := range tokenOutputs {
						tokenOutputIDs = append(tokenOutputIDs, output.ID)
						if output.Edges.OutputCreatedTokenTransaction != nil {
							transactionIDSet[output.Edges.OutputCreatedTokenTransaction.ID] = struct{}{}
						}
						if output.Edges.OutputSpentTokenTransaction != nil {
							transactionIDSet[output.Edges.OutputSpentTokenTransaction.ID] = struct{}{}
						}
					}

					for txID := range transactionIDSet {
						tokenTransactionIDs = append(tokenTransactionIDs, txID)
					}

					logger.Info("Collected entity IDs for deletion",
						"token_outputs", len(tokenOutputIDs),
						"token_transactions", len(tokenTransactionIDs))

					deletedOutputs, err := tx.TokenOutput.Delete().
						Where(tokenoutput.IDIn(tokenOutputIDs...)).
						Exec(ctx)
					if err != nil {
						return fmt.Errorf("failed to delete token outputs: %w", err)
					}
					logger.Info("Deleted token outputs", "count", deletedOutputs)

					if len(tokenTransactionIDs) > 0 {
						deletedTransactions, err := tx.TokenTransaction.Delete().
							Where(tokentransaction.IDIn(tokenTransactionIDs...)).
							Exec(ctx)
						if err != nil {
							return fmt.Errorf("failed to delete token transactions: %w", err)
						}
						logger.Info("Deleted token transactions", "count", deletedTransactions)
					}

					logger.Info("Successfully completed deletion of legacy token output data",
						"total_token_outputs_deleted", deletedOutputs,
						"total_token_transactions_deleted", len(tokenTransactionIDs))

					return nil
				},
			},
		},
	}
}

func (t *BaseTaskSpec) getTimeout() time.Duration {
	if t.Timeout != nil {
		return *t.Timeout
	}
	return defaultTaskTimeout
}

func (t *BaseTaskSpec) RunOnce(config *so.Config, dbClient *ent.Client) error {
	ctx := context.Background()

	wrappedTask := t.chainMiddleware(
		LogMiddleware(),
		PanicRecoveryMiddleware(),
		TimeoutMiddleware(),
		DatabaseMiddleware(db.NewDefaultSessionFactory(dbClient, config.Database.NewTxTimeout)),
	)

	return wrappedTask.Task(ctx, config)
}

func (t *ScheduledTaskSpec) Schedule(scheduler gocron.Scheduler, config *so.Config, dbClient *ent.Client) error {
	wrappedTask := t.chainMiddleware(
		LogMiddleware(),
		PanicRecoveryMiddleware(),
		TimeoutMiddleware(),
		DatabaseMiddleware(db.NewDefaultSessionFactory(dbClient, config.Database.NewTxTimeout)),
	)

	_, err := scheduler.NewJob(
		gocron.DurationJob(t.ExecutionInterval),
		gocron.NewTask(wrappedTask.Task, config),
		gocron.WithName(t.Name),
	)
	if err != nil {
		return err
	}

	return nil
}

// Wrap the task with the given middleware. This returns a new BaseTaskSpec whose Task function
// is wrapped with the provided middleware. The original task's fields are preserved.
func (t *BaseTaskSpec) wrapMiddleware(middleware TaskMiddleware) *BaseTaskSpec {
	return &BaseTaskSpec{
		Name:         t.Name,
		Timeout:      t.Timeout,
		RunInTestEnv: t.RunInTestEnv,
		Task: func(ctx context.Context, config *so.Config) error {
			return middleware(ctx, config, t)
		},
	}
}

// Wrap the task with the given middlewares chained together. The middlewares have their ordering
// preserved, so the first middelware in the slice will be the outermost, and the last middleware
// will be the innermost.
//
// +------- Middleware 1 -------+
// | +----- Middleware 2 -----+ |
// | | +--- Middleware 3 ---+ | |
// | | |                    | | |
// | | |   Task (t.Task)    | | |
// | | |                    | | |
// | | +--------------------+ | |
// | +------------------------+ |
// +----------------------------+
//
// Once the task has completed, the middlewares will be unwound in reverse order, so the last
// middleware will be the first to complete.
func (t *BaseTaskSpec) chainMiddleware(
	middlewares ...TaskMiddleware,
) *BaseTaskSpec {
	// Apply the middleware to the task so that the last middleware is the inner most.
	currTask := t

	for i := len(middlewares) - 1; i >= 0; i-- {
		innerTask, i := currTask, i
		currTask = innerTask.wrapMiddleware(middlewares[i])
	}

	return currTask
}

// RunStartupTasks runs startup tasks with optional retry logic.
// Any task with a non-nil RetryInterval will be retried in the background on failure.
func RunStartupTasks(config *so.Config, db *ent.Client, runningLocally bool) error {
	slog.Info("Running startup tasks...")

	for _, task := range AllStartupTasks() {
		if !runningLocally || task.RunInTestEnv {
			if task.RetryInterval != nil {
				go func(task StartupTaskSpec) {
					retryInterval := *task.RetryInterval

					for {
						err := task.RunOnce(config, db)
						if err == nil {
							break
						}

						if errors.Is(err, errTaskTimeout) {
							break
						}

						slog.Warn(fmt.Sprintf("Startup task failed, retrying in %s", retryInterval), "task.name", task.Name, "error", err)
						time.Sleep(retryInterval)
					}
				}(task)
			} else {
				task.RunOnce(config, db) // nolint: errcheck
			}
		}
	}
	slog.Info("All startup tasks completed")
	return nil
}
