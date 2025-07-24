package task

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/lightsparkdev/spark/so/handler/tokens"
	"github.com/lightsparkdev/spark/so/helper"

	"entgo.io/ent/dialect/sql"
	"github.com/go-co-op/gocron/v2"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/logging"
	pbspark "github.com/lightsparkdev/spark/proto/spark"
	pbinternal "github.com/lightsparkdev/spark/proto/spark_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/ent/gossip"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/tokenfreeze"
	"github.com/lightsparkdev/spark/so/ent/tokenoutput"
	"github.com/lightsparkdev/spark/so/ent/tokentransaction"
	"github.com/lightsparkdev/spark/so/ent/transfer"
	"github.com/lightsparkdev/spark/so/ent/tree"
	"github.com/lightsparkdev/spark/so/ent/treenode"
	"github.com/lightsparkdev/spark/so/ent/utxoswap"
	"github.com/lightsparkdev/spark/so/handler"
	"github.com/lightsparkdev/spark/so/lrc20"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	defaultTaskTimeout              = 1 * time.Minute
	dkgTaskTimeout                  = 3 * time.Minute
	deleteStaleTreeNodesTaskTimeout = 10 * time.Minute

	errTaskTimeout = fmt.Errorf("task timed out")
)

// BaseTask contains common fields for all task types.
type BaseTask struct {
	// Name is the human-readable name of the task.
	Name string
	// Timeout is the maximum time the task is allowed to run before it will be cancelled.
	Timeout *time.Duration
	// Whether to run the task in the hermetic test environment.
	RunInTestEnv bool
	// If true, the task will not run
	Disabled bool
	// Task is the function that is run when the task is scheduled.
	Task func(context.Context, *so.Config, *lrc20.Client) error
}

// ScheduledTask is a task that runs on a schedule.
type ScheduledTask struct {
	BaseTask
	// ExecutionInterval is the interval between each run of the task.
	ExecutionInterval time.Duration
}

// StartupTask is a task that runs once at startup.
type StartupTask struct {
	BaseTask
	// RetryInterval is the interval between retries for startup tasks. If nil, no retries are performed.
	// Retries may be necessary if a startup task is dependent on other asynchronous setup, such as internal
	// GRPCs to other operators that may not be ready immediately upon the startup of this operator.
	RetryInterval *time.Duration
}

// AllScheduledTasks returns all the tasks that are scheduled to run.
func AllScheduledTasks() []ScheduledTask {
	return []ScheduledTask{
		{
			ExecutionInterval: 10 * time.Second,
			BaseTask: BaseTask{
				Name:         "dkg",
				Timeout:      &dkgTaskTimeout,
				RunInTestEnv: true,
				Task: func(ctx context.Context, config *so.Config, _ *lrc20.Client) error {
					return ent.RunDKGIfNeeded(ctx, config)
				},
			},
		},
		{
			ExecutionInterval: 1 * time.Minute,
			BaseTask: BaseTask{
				Name:         "cancel_expired_transfers",
				RunInTestEnv: true,
				Task: func(ctx context.Context, config *so.Config, _ *lrc20.Client) error {
					logger := logging.GetLoggerFromContext(ctx)
					h := handler.NewTransferHandler(config)

					tx, err := ent.GetDbFromContext(ctx)
					if err != nil {
						return fmt.Errorf("failed to get or create current tx for request: %w", err)
					}
					query := tx.Transfer.Query().Where(
						transfer.And(
							transfer.StatusIn(st.TransferStatusSenderInitiated, st.TransferStatusSenderKeyTweakPending),
							transfer.ExpiryTimeLT(time.Now()),
							transfer.ExpiryTimeNEQ(time.Unix(0, 0)),
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
			BaseTask: BaseTask{
				Name:         "delete_stale_pending_trees",
				Timeout:      &deleteStaleTreeNodesTaskTimeout,
				RunInTestEnv: false,
				// TODO(LIG-7896): This task keeps on getting stuck on
				// very large trees. Disabling for now as we investigate
				Disabled: true,
				Task: func(ctx context.Context, _ *so.Config, _ *lrc20.Client) error {
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
			BaseTask: BaseTask{
				Name: "resume_send_transfer",
				Task: func(ctx context.Context, config *so.Config, _ *lrc20.Client) error {
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
			BaseTask: BaseTask{
				Name:         "cancel_or_finalize_expired_token_transactions",
				RunInTestEnv: true,
				Task: func(ctx context.Context, config *so.Config, lrc20Client *lrc20.Client) error {
					logger := logging.GetLoggerFromContext(ctx)
					currentTime := time.Now()

					h := tokens.NewInternalFinalizeTokenHandler(config, lrc20Client)
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
			ExecutionInterval: 5 * time.Minute,
			BaseTask: BaseTask{
				Name:         "send_gossip",
				RunInTestEnv: true,
				Task: func(ctx context.Context, config *so.Config, _ *lrc20.Client) error {
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
			BaseTask: BaseTask{
				Name:         "complete_utxo_swap",
				RunInTestEnv: true,
				Task: func(ctx context.Context, config *so.Config, _ *lrc20.Client) error {
					logger := logging.GetLoggerFromContext(ctx)
					tx, err := ent.GetDbFromContext(ctx)
					if err != nil {
						return fmt.Errorf("failed to get or create current tx for request: %w", err)
					}

					query := tx.UtxoSwap.Query().
						Where(utxoswap.StatusEQ(st.UtxoSwapStatusCreated)).
						Where(utxoswap.CoordinatorIdentityPublicKeyEQ(config.IdentityPublicKey())).
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

func AllStartupTasks() []StartupTask {
	entityDkgTaskTimeout := 5 * time.Minute
	entityDkgRetryInterval := 10 * time.Second
	backfillTokenOutputInterval := 10 * time.Minute

	return []StartupTask{
		{
			RetryInterval: &entityDkgRetryInterval,
			BaseTask: BaseTask{
				Name:         "maybe_reserve_entity_dkg",
				RunInTestEnv: true,
				Timeout:      &entityDkgTaskTimeout,
				Task: func(ctx context.Context, config *so.Config, _ *lrc20.Client) error {
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
			BaseTask: BaseTask{
				Name:         "backfill_token_freezes_token_identifier",
				RunInTestEnv: true,
				Task: func(ctx context.Context, config *so.Config, _ *lrc20.Client) error {
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
			BaseTask: BaseTask{
				Name:         "backfill_token_output_token_identifiers_and_token_create_edges",
				RunInTestEnv: true,
				Task: func(ctx context.Context, config *so.Config, _ *lrc20.Client) error {
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
	}
}

func (t *BaseTask) getTimeout() time.Duration {
	if t.Timeout != nil {
		return *t.Timeout
	}
	return defaultTaskTimeout
}

func (t *BaseTask) RunOnce(config *so.Config, db *ent.Client, lrc20Client *lrc20.Client) error {
	ctx := context.Background()
	wrappedTask := t.createWrappedTask()
	return wrappedTask(ctx, config, db, lrc20Client)
}

func (t *BaseTask) createWrappedTask() func(ctx context.Context, cfg *so.Config, dbClient *ent.Client, lrc20 *lrc20.Client) error {
	return func(ctx context.Context, cfg *so.Config, dbClient *ent.Client, lrc20Client *lrc20.Client) error {
		logger := logging.GetLoggerFromContext(ctx).
			With("task.name", t.Name).
			With("task.id", uuid.New().String())

		ctx = logging.Inject(ctx, logger)

		timeout := t.getTimeout()
		ctx, cancel := context.WithTimeoutCause(ctx, timeout, errTaskTimeout)
		defer cancel()

		done := make(chan error, 1)

		inner := func(ctx context.Context, cfg *so.Config, lrc20Client *lrc20.Client, dbClient *ent.Client) error {
			dbSession := db.NewSession(dbClient, cfg.Database.NewTxTimeout)
			ctx = ent.Inject(ctx, dbSession)
			err := t.Task(ctx, cfg, lrc20Client)
			if err != nil {
				logger.Error("Task failed!", "error", err)

				if tx := dbSession.GetTxIfExists(); tx != nil {
					rollbackErr := tx.Rollback()
					if rollbackErr != nil {
						logger.Warn("Failed to rollback transaction after task failure", "error", rollbackErr)
					}
				}

				return err
			}

			if tx := dbSession.GetTxIfExists(); tx != nil {
				return tx.Commit()
			}
			return nil
		}

		logger.Info("Starting task")

		go func() {
			done <- inner(ctx, cfg, lrc20Client, dbClient)
		}()

		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			if context.Cause(ctx) == errTaskTimeout {
				logger.Warn("Task timed out!")
				return ctx.Err()
			}

			logger.Warn("Context done before task completion! Are we shutting down?", "error", ctx.Err())
			return ctx.Err()
		}
	}
}

func (t *ScheduledTask) Schedule(
	scheduler gocron.Scheduler,
	config *so.Config,
	db *ent.Client,
	lrc20Client *lrc20.Client,
) error {
	_, err := scheduler.NewJob(
		gocron.DurationJob(t.ExecutionInterval),
		gocron.NewTask(t.createWrappedTask(), config, db, lrc20Client),
		gocron.WithName(t.Name),
	)
	if err != nil {
		return err
	}

	return nil
}

type Monitor struct {
	taskCount    metric.Int64Counter
	taskDuration metric.Float64Histogram
}

func NewMonitor() (*Monitor, error) {
	meter := otel.Meter("gocron")

	jobCount, err := meter.Int64Counter(
		"gocron.task_count_total",
		metric.WithDescription("Total number of tasks executed"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create task count metric: %w", err)
	}

	jobDuration, err := meter.Float64Histogram(
		"gocron.task_duration_milliseconds",
		metric.WithDescription("Duration of tasks in milliseconds."),
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries(
			// Replace the buckets at the lower end (e.g. 5, 10, 25, 50, 75ms) with buckets up to 60s, to
			// capture the longer task durations.
			100, 250, 500, 750, 1000, 2500, 5000, 7500, 10000, 15000, 30000, 45000, 60000,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create task duration metric: %w", err)
	}

	return &Monitor{
		taskCount:    jobCount,
		taskDuration: jobDuration,
	}, nil
}

func (t *Monitor) IncrementJob(_ uuid.UUID, name string, _ []string, status gocron.JobStatus) {
	t.taskCount.Add(
		context.Background(),
		1,
		metric.WithAttributes(
			attribute.String("task.name", name),
			attribute.String("task.result", string(status)),
		),
	)
}

func (t *Monitor) RecordJobTiming(startTime, endTime time.Time, _ uuid.UUID, name string, _ []string) {
	duration := endTime.Sub(startTime).Milliseconds()
	t.taskDuration.Record(
		context.Background(),
		float64(duration),
		metric.WithAttributes(
			attribute.String("task.name", name),
		),
	)
}

// RunStartupTasks runs startup tasks with optional retry logic.
// Any task with a non-nil RetryInterval will be retried in the background on failure.
func RunStartupTasks(config *so.Config, db *ent.Client, lrc20Client *lrc20.Client, runningLocally bool) error {
	slog.Info("Running startup tasks...")

	for _, task := range AllStartupTasks() {
		if !runningLocally || task.RunInTestEnv {
			slog.Info("Running startup task", "task", task.Name)

			if task.RetryInterval != nil {
				go func(task StartupTask) {
					timeout := task.getTimeout()
					retryInterval := *task.RetryInterval

					startTime := time.Now()
					for {
						err := task.RunOnce(config, db, lrc20Client)
						if err == nil {
							slog.Info("Startup task completed successfully", "task", task.Name)
							break
						}

						if time.Since(startTime) >= timeout {
							slog.Error("Startup task failed after timeout", "task", task.Name, "timeout", timeout, "error", err)
							break
						}

						slog.Warn("Startup task failed, retrying", "task", task.Name, "error", err, "retry_in", retryInterval)
						time.Sleep(retryInterval)
					}
				}(task)
			} else {
				err := task.RunOnce(config, db, lrc20Client)
				if err != nil {
					slog.Error("Startup task failed", "task", task.Name, "error", err)
				} else {
					slog.Info("Startup task completed successfully", "task", task.Name)
				}
			}
		}
	}
	slog.Info("All startup tasks completed")
	return nil
}
