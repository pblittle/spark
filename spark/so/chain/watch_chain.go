package chain

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"maps"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/logging"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/ent/blockheight"
	"github.com/lightsparkdev/spark/so/ent/cooperativeexit"
	"github.com/lightsparkdev/spark/so/ent/depositaddress"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/signingkeyshare"
	"github.com/lightsparkdev/spark/so/ent/treenode"
	"github.com/lightsparkdev/spark/so/helper"
	"github.com/lightsparkdev/spark/so/watchtower"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/protobuf/proto"
)

var (
	meter = otel.Meter("chain_watcher")

	// Metrics
	eligibleNodesGauge                 metric.Int64Gauge
	blockHeightGauge                   metric.Int64Gauge
	blockHeightProcessingTimeHistogram metric.Int64Histogram
)

func init() {
	var err error

	eligibleNodesGauge, err = meter.Int64Gauge(
		"chain_watcher.eligible_nodes",
		metric.WithDescription("Number of nodes eligible for timelock expiry checks"),
	)
	if err != nil {
		logging.GetLoggerFromContext(context.Background()).Error("Failed to create eligible nodes gauge", "error", err)
	}

	blockHeightGauge, err = meter.Int64Gauge(
		"chain_watcher.current_block_height",
		metric.WithDescription("Current block height processed by chain watcher"),
	)
	if err != nil {
		logging.GetLoggerFromContext(context.Background()).Error("Failed to create block height gauge", "error", err)
	}

	blockHeightProcessingTimeHistogram, err = meter.Int64Histogram(
		"chain_watcher.block_height_processing_time_milliseconds",
		metric.WithDescription("Time taken to process a block"),
		metric.WithExplicitBucketBoundaries(
			3000,   // 3 seconds (fast processing)
			7000,   // 7 seconds (below average)
			10000,  // 10 seconds (average)
			20000,  // 20 seconds (above average)
			60000,  // 1 minute (slow)
			120000, // 2 minutes (very slow)
			180000, // 3 minutes (maximum expected)
		),
	)
	if err != nil {
		logging.GetLoggerFromContext(context.Background()).Error("Failed to create block height processing time histogram", "error", err)
	}
}

func pollInterval(network common.Network) time.Duration {
	switch network {
	case common.Mainnet:
		return 1 * time.Minute
	case common.Testnet:
		return 1 * time.Minute
	case common.Regtest:
		return 3 * time.Second
	case common.Signet:
		return 3 * time.Second
	default:
		return 1 * time.Minute
	}
}

// Tip represents the tip of a blockchain.
type Tip struct {
	Height int64
	Hash   chainhash.Hash
}

// NewTip creates a new ChainTip.
func NewTip(height int64, hash chainhash.Hash) Tip {
	return Tip{Height: height, Hash: hash}
}

// Difference represents the difference between two chain tips
// that needs to be rescanned.
type Difference struct {
	CommonAncestor Tip
	Disconnected   []Tip
	Connected      []Tip
}

func findPreviousChainTip(chainTip Tip, client *rpcclient.Client) (Tip, error) {
	blockResp, err := client.GetBlockVerbose(&chainTip.Hash)
	if err != nil {
		return Tip{}, err
	}
	var prevHash chainhash.Hash
	err = chainhash.Decode(&prevHash, blockResp.PreviousHash)
	if err != nil {
		return Tip{}, err
	}
	return Tip{Height: blockResp.Height - 1, Hash: prevHash}, nil
}

func findDifference(currChainTip, newChainTip Tip, client *rpcclient.Client) (Difference, error) {
	var disconnected []Tip
	var connected []Tip

	for !currChainTip.Hash.IsEqual(&newChainTip.Hash) {
		// Walk back the chain, finding blocks needed to connect and disconnect. Only walk back
		// the header with the greater height, or both if equal heights (i.e. same height, different hashes!).
		newHeight := newChainTip.Height
		currHeight := currChainTip.Height
		if newHeight <= currHeight {
			disconnected = append(disconnected, currChainTip)
			prevChainTip, err := findPreviousChainTip(currChainTip, client)
			if err != nil {
				return Difference{}, err
			}
			currChainTip = prevChainTip
		}
		if newHeight >= currHeight {
			connected = append([]Tip{newChainTip}, connected...)
			prevChainTip, err := findPreviousChainTip(newChainTip, client)
			if err != nil {
				return Difference{}, err
			}
			newChainTip = prevChainTip
		}
	}

	return Difference{
		CommonAncestor: newChainTip,
		Disconnected:   disconnected,
		Connected:      connected,
	}, nil
}

func scanChainUpdates(
	ctx context.Context,
	config *so.Config,
	dbClient *ent.Client,
	bitcoinClient *rpcclient.Client,
	network common.Network,
) error {
	logger := logging.GetLoggerFromContext(ctx)
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic recovered in scanChainUpdates", "panic", r, "stack", string(debug.Stack()))
		}
	}()

	latestBlockHeight, err := bitcoinClient.GetBlockCount()
	if err != nil {
		return fmt.Errorf("failed to get block count: %w", err)
	}
	latestBlockHash, err := bitcoinClient.GetBlockHash(latestBlockHeight)
	if err != nil {
		return fmt.Errorf("failed to get block hash at height %d: %w", latestBlockHeight, err)
	}
	latestChainTip := NewTip(latestBlockHeight, *latestBlockHash)
	logger.Info("Latest chain tip", "height", latestBlockHeight, "hash", latestBlockHash.String())

	entNetwork := common.SchemaNetwork(network)
	dbBlockHeight, err := dbClient.BlockHeight.Query().
		Where(blockheight.NetworkEQ(entNetwork)).
		Only(ctx)
	if ent.IsNotFound(err) {
		startHeight := max(0, latestBlockHeight-6)
		logger.Info("Block height not found, creating new entry", "height", startHeight)
		dbBlockHeight, err = dbClient.BlockHeight.Create().SetHeight(startHeight).SetNetwork(entNetwork).Save(ctx)
	}
	if err != nil {
		return fmt.Errorf("failed to query block height: %w", err)
	}
	dbBlockHash, err := bitcoinClient.GetBlockHash(dbBlockHeight.Height)
	if err != nil {
		return fmt.Errorf("failed to get block hash at db height %d: %w", dbBlockHeight.Height, err)
	}

	dbChainTip := NewTip(dbBlockHeight.Height, *dbBlockHash)
	logger.Info("DB chain tip", "height", dbBlockHeight.Height, "hash", dbBlockHash.String())
	difference, err := findDifference(dbChainTip, latestChainTip, bitcoinClient)
	if err != nil {
		return fmt.Errorf("failed to find difference: %w", err)
	}
	err = disconnectBlocks(ctx, dbClient, difference.Disconnected, network)
	if err != nil {
		return fmt.Errorf("failed to disconnect blocks: %w", err)
	}
	err = connectBlocks(
		ctx,
		config,
		dbClient,
		bitcoinClient,
		difference.Connected,
		network,
	)
	logger.Info("Connected blocks", "count", len(difference.Connected))
	if err != nil {
		return fmt.Errorf("failed to connect blocks: %w", err)
	}
	return nil
}

func RPCClientConfig(cfg so.BitcoindConfig) rpcclient.ConnConfig {
	return rpcclient.ConnConfig{
		Host:         cfg.Host,
		User:         cfg.User,
		Pass:         cfg.Password,
		Params:       cfg.Network,
		DisableTLS:   true, // TODO: PE help
		HTTPPostMode: true,
	}
}

func WatchChain(
	ctx context.Context,
	config *so.Config,
	dbClient *ent.Client,
	bitcoindConfig so.BitcoindConfig,
) error {
	logger := logging.GetLoggerFromContext(ctx)

	network, err := common.NetworkFromString(bitcoindConfig.Network)
	if err != nil {
		return err
	}
	connConfig := RPCClientConfig(bitcoindConfig)
	bitcoinClient, err := rpcclient.New(&connConfig, nil)
	if err != nil {
		return err
	}

	err = scanChainUpdates(ctx, config, dbClient, bitcoinClient, network)
	if err != nil {
		logger.Error("failed to scan chain updates", "error", err)
	}

	zmqSubscriber, err := NewZmqSubscriber()
	if err != nil {
		return err
	}

	defer func() {
		err := zmqSubscriber.Close()
		if err != nil {
			logger.Warn("Failed to close ZMQ subscriber", "error", err)
		}
	}()

	newBlockNotification, errChan, err := zmqSubscriber.Subscribe(ctx, bitcoindConfig.ZmqPubRawBlock, "rawblock")
	if err != nil {
		return err
	}

	// TODO: we should consider alerting on errors within this loop
	for {
		select {
		case err := <-errChan:
			logger.Error("Error receiving ZMQ message", "error", err)
			return err
		case <-ctx.Done():
			logger.Info("Context done, stopping chain watcher")
			return nil
		case <-newBlockNotification:
		case <-time.After(pollInterval(network)):
		}
		// We don't actually do anything with the block receive since
		// we need to query bitcoind for the height anyway. We just
		// treat it as a notification that a new block appeared.

		err = scanChainUpdates(ctx, config, dbClient, bitcoinClient, network)
		if err != nil {
			logger.Error("Failed to scan chain updates", "error", err)
		}
	}
}

func disconnectBlocks(_ context.Context, _ *ent.Client, _ []Tip, _ common.Network) error {
	// TODO(DL-100): Add handling for disconnected token withdrawal transactions.
	return nil
}

func connectBlocks(
	ctx context.Context,
	config *so.Config,
	dbClient *ent.Client,
	bitcoinClient *rpcclient.Client,
	chainTips []Tip,
	network common.Network,
) error {
	logger := logging.GetLoggerFromContext(ctx)

	for _, chainTip := range chainTips {
		blockHash, err := bitcoinClient.GetBlockHash(chainTip.Height)
		if err != nil {
			return err
		}
		block, err := bitcoinClient.GetBlockVerboseTx(blockHash)
		if err != nil {
			return err
		}
		var txs []wire.MsgTx
		for _, tx := range block.Tx {
			rawTx, err := TxFromRPCTx(tx)
			if err != nil {
				return err
			}
			txs = append(txs, rawTx)
		}

		dbTx, err := dbClient.Tx(ctx)
		if err != nil {
			return err
		}
		err = handleBlock(
			ctx,
			config,
			dbTx,
			bitcoinClient,
			txs,
			chainTip.Height,
			network,
		)
		if err != nil {
			logger.Error("Failed to handle block", "error", err)
			rollbackErr := dbTx.Rollback()
			if rollbackErr != nil {
				return rollbackErr
			}
			return err
		}
		err = dbTx.Commit()
		if err != nil {
			return err
		}

		// Record current block height
		if blockHeightGauge != nil {
			blockHeightGauge.Record(ctx, chainTip.Height, metric.WithAttributes(
				attribute.String("network", network.String()),
			))
		}
	}
	return nil
}

func TxFromRPCTx(txs btcjson.TxRawResult) (wire.MsgTx, error) {
	rawTxBytes, err := hex.DecodeString(txs.Hex)
	if err != nil {
		return wire.MsgTx{}, err
	}
	r := bytes.NewReader(rawTxBytes)
	var tx wire.MsgTx
	err = tx.Deserialize(r)
	if err != nil {
		return wire.MsgTx{}, err
	}
	return tx, nil
}

type AddressDepositUtxo struct {
	tx     *wire.MsgTx
	amount uint64
	idx    uint32
}

// processTransactions processes a list of transactions and returns:
// - A map of confirmed transaction hashes
// - A list of debited addresses
// - A map of addresses to their UTXOs
func processTransactions(txs []wire.MsgTx, networkParams *chaincfg.Params) (map[[32]byte]bool, []string, map[string][]AddressDepositUtxo, error) {
	confirmedTxHashSet := make(map[[32]byte]bool)
	creditedAddresses := make(map[string]bool)
	addressToUtxoMap := make(map[string][]AddressDepositUtxo)

	for _, tx := range txs {
		for idx, txOut := range tx.TxOut {
			_, addresses, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, networkParams)
			if err != nil {
				continue
			}
			for _, address := range addresses {
				creditedAddresses[address.EncodeAddress()] = true
				addressToUtxoMap[address.EncodeAddress()] = append(addressToUtxoMap[address.EncodeAddress()], AddressDepositUtxo{&tx, uint64(txOut.Value), uint32(idx)})
			}
		}
		txid := tx.TxHash()
		confirmedTxHashSet[txid] = true
	}

	return confirmedTxHashSet, slices.Collect(maps.Keys(creditedAddresses)), addressToUtxoMap, nil
}

func handleBlock(
	ctx context.Context,
	config *so.Config,
	dbTx *ent.Tx,
	bitcoinClient *rpcclient.Client,
	txs []wire.MsgTx,
	blockHeight int64,
	network common.Network,
) error {
	logger := logging.GetLoggerFromContext(ctx)
	start := time.Now()
	logger.Info("Starting to handle block", "height", blockHeight)

	networkParams := common.NetworkParams(network)
	_, err := dbTx.BlockHeight.Update().
		SetHeight(blockHeight).
		Where(blockheight.NetworkEQ(common.SchemaNetwork(network))).
		Save(ctx)
	if err != nil {
		return err
	}
	handleTokenUpdatesForBlock(ctx, config, dbTx, txs, blockHeight, network)

	confirmedTxHashSet, creditedAddresses, addressToUtxoMap, err := processTransactions(txs, networkParams)
	if err != nil {
		return err
	}

	processNodesForWatchtowers := true
	if bitcoinConfig, ok := config.BitcoindConfigs[strings.ToLower(network.String())]; ok {
		if bitcoinConfig.ProcessNodesForWatchtowers != nil {
			processNodesForWatchtowers = *bitcoinConfig.ProcessNodesForWatchtowers
		}
	}

	if processNodesForWatchtowers {
		logger.Info("Started processing nodes for watchtowers", "height", blockHeight)
		// Fetch only nodes that could have expired timelocks
		nodes, err := watchtower.QueryNodesWithExpiredTimeLocks(ctx, dbTx, blockHeight, network)
		if err != nil {
			return fmt.Errorf("failed to query nodes: %w", err)
		}

		// Record number of eligible nodes for timelock checks
		if eligibleNodesGauge != nil {
			eligibleNodesGauge.Record(ctx, int64(len(nodes)), metric.WithAttributes(
				attribute.String("network", network.String()),
			))
		}

		for _, node := range nodes {
			cpfpTx, err := common.TxFromRawTxBytes(node.RawTx)
			if err != nil {
				return fmt.Errorf("failed to parse node tx: %w", err)
			}

			cpfpTxid := cpfpTx.TxHash()
			if confirmedTxHashSet[cpfpTxid] {
				_, err = dbTx.TreeNode.UpdateOne(node).
					SetNodeConfirmationHeight(uint64(blockHeight)).
					SetStatus(st.TreeNodeStatusOnChain).
					Save(ctx)
				if err != nil {
					return fmt.Errorf("failed to update node status: %w", err)
				}
				logger.Info("Updated tree node status to ON_CHAIN",
					"node_id", node.ID,
					"cpfp_tx_hash", cpfpTxid.String(),
					"block_height", blockHeight)
			}

			if len(node.DirectTx) > 0 {
				directTx, err := common.TxFromRawTxBytes(node.DirectTx)
				if err != nil {
					return fmt.Errorf("failed to parse direct node tx: %w", err)
				}
				directTxid := directTx.TxHash()
				if confirmedTxHashSet[directTxid] {
					_, err = dbTx.TreeNode.UpdateOne(node).
						SetNodeConfirmationHeight(uint64(blockHeight)).
						SetStatus(st.TreeNodeStatusOnChain).
						Save(ctx)
					if err != nil {
						return fmt.Errorf("failed to update node status: %w", err)
					}
					logger.Info("Updated tree node status to ON_CHAIN",
						"node_id", node.ID,
						"direct_tx_hash", directTxid.String(),
						"block_height", blockHeight)
				}
			}

			if len(node.RawRefundTx) > 0 {
				cpfpRefundTx, err := common.TxFromRawTxBytes(node.RawRefundTx)
				if err != nil {
					return fmt.Errorf("failed to parse cpfp refund tx: %w", err)
				}

				cpfpRefundTxid := cpfpRefundTx.TxHash()

				if confirmedTxHashSet[cpfpRefundTxid] {
					_, err = dbTx.TreeNode.UpdateOne(node).
						SetRefundConfirmationHeight(uint64(blockHeight)).
						SetStatus(st.TreeNodeStatusExited).
						Save(ctx)
					if err != nil {
						return fmt.Errorf("failed to update node refund status: %w", err)
					}
					logger.Info("Updated tree node status to EXITED",
						"node_id", node.ID,
						"refund_tx_hash", cpfpRefundTxid.String(),
						"block_height", blockHeight)
				}

				if len(node.DirectRefundTx) > 0 {
					directRefundTx, err := common.TxFromRawTxBytes(node.DirectRefundTx)
					if err != nil {
						return fmt.Errorf("failed to parse cpfp refund tx: %w", err)
					}
					directRefundTxid := directRefundTx.TxHash()
					if confirmedTxHashSet[directRefundTxid] {
						_, err = dbTx.TreeNode.UpdateOne(node).
							SetRefundConfirmationHeight(uint64(blockHeight)).
							SetStatus(st.TreeNodeStatusExited).
							Save(ctx)
						if err != nil {
							return fmt.Errorf("failed to update node status: %w", err)
						}
						logger.Info("Updated tree node status to ON_CHAIN",
							"node_id", node.ID,
							"direct_refund_tx_hash", directRefundTxid.String(),
							"block_height", blockHeight)
					}
				}

				if len(node.DirectFromCpfpRefundTx) > 0 {
					directFromCpfpRefundTx, err := common.TxFromRawTxBytes(node.DirectFromCpfpRefundTx)
					if err != nil {
						return fmt.Errorf("failed to parse cpfp refund tx: %w", err)
					}
					directFromCpfpRefundTxid := directFromCpfpRefundTx.TxHash()
					if confirmedTxHashSet[directFromCpfpRefundTxid] {
						_, err = dbTx.TreeNode.UpdateOne(node).
							SetRefundConfirmationHeight(uint64(blockHeight)).
							SetStatus(st.TreeNodeStatusExited).
							Save(ctx)
						if err != nil {
							return fmt.Errorf("failed to update node status: %w", err)
						}
						logger.Info("Updated tree node status to ON_CHAIN",
							"node_id", node.ID,
							"direct_from_cpfp_refund_tx_hash", directFromCpfpRefundTxid.String(),
							"block_height", blockHeight)
					}
				}
			}

			// Check if node or refund TX timelock has expired
			if err := watchtower.CheckExpiredTimeLocks(ctx, bitcoinClient, node, blockHeight, network); err != nil {
				logger.Error("Failed to check expired time locks", "error", err)
			}
		}
	}
	logger.Info("Started processing coop exits", "height", blockHeight)
	// TODO: expire pending coop exits after some time so this doesn't become too large
	pendingCoopExits, err := dbTx.CooperativeExit.Query().Where(cooperativeexit.ConfirmationHeightIsNil()).All(ctx)
	if err != nil {
		return err
	}
	for _, coopExit := range pendingCoopExits {
		txHash := coopExit.ExitTxid
		reversedHash := slices.Clone(txHash)
		slices.Reverse(reversedHash)
		_, found := confirmedTxHashSet[[32]byte(txHash)]
		_, reverseFound := confirmedTxHashSet[[32]byte(reversedHash)]
		if found {
			logger.Debug("Found BE coop exit tx.", "txHash", txHash)
		} else if reverseFound {
			logger.Debug("Found LE coop exit tx.", "txHash", txHash)
		} else {
			continue
		}
		// Set confirmation height for the coop exit.
		_, err = coopExit.Update().SetConfirmationHeight(blockHeight).Save(ctx)
		if err != nil {
			return fmt.Errorf("failed to update coop exit %s: %w", coopExit.ID.String(), err)
		}

		// Attempt to tweak keys for the coop exit. Ok to log the error and continue here
		// since this is not critical for the block processing.
		err = tweakKeysForCoopExit(ctx, coopExit, blockHeight)
		if err != nil {
			logger.Error("failed to handle coop exit confirmation", "error", err, "coop_exit_id", coopExit.ID)
			continue
		}
	}

	logger.Info("Started processing static deposits", "height", blockHeight)
	err = storeStaticDeposits(ctx, dbTx, creditedAddresses, addressToUtxoMap, network, blockHeight)
	if err != nil {
		return fmt.Errorf("failed to store static deposits: %w", err)
	}

	logger.Info("Started processing confirmed deposits", "height", blockHeight)
	confirmedDeposits, err := dbTx.DepositAddress.Query().
		Where(depositaddress.ConfirmationHeightIsNil()).
		Where(depositaddress.IsStaticEQ(false)).
		Where(depositaddress.AddressIn(creditedAddresses...)).
		All(ctx)
	if err != nil {
		return err
	}
	for _, deposit := range confirmedDeposits {
		// TODO: only unlock if deposit reaches X confirmations
		utxos, ok := addressToUtxoMap[deposit.Address]
		if !ok || len(utxos) == 0 {
			logger.Info("UTXO not found for deposit address", "address", deposit.Address)
			continue
		}
		if len(utxos) > 1 {
			logger.Warn("Multiple UTXOs found for a single use deposit address, picking the first one", "address", deposit.Address)
		}
		utxo := utxos[0]
		_, err = dbTx.DepositAddress.UpdateOne(deposit).
			SetConfirmationHeight(blockHeight).
			SetConfirmationTxid(utxo.tx.TxHash().String()).
			Save(ctx)
		if err != nil {
			return err
		}
		signingKeyShare, err := deposit.QuerySigningKeyshare().Only(ctx)
		if err != nil {
			return err
		}
		treeNode, err := dbTx.TreeNode.Query().
			Where(treenode.HasSigningKeyshareWith(signingkeyshare.ID(signingKeyShare.ID))).
			// FIXME(mhr): Unblocking deployment. Is this what we should do if we encounter a tree node that
			// has already been marked available (e.g. through `FinalizeNodeSignatures`)?
			Where(treenode.StatusEQ(st.TreeNodeStatusCreating)).
			Only(ctx)
		if ent.IsNotFound(err) {
			logger.Info("Deposit confirmed before tree creation or tree already available", "address", deposit.Address)
			continue
		}
		if err != nil {
			return err
		}
		logger.Info("Found tree node", "node", treeNode.ID)
		if treeNode.Status != st.TreeNodeStatusCreating {
			logger.Info("Expected tree node status to be creating", "status", treeNode.Status)
		}
		tree, err := treeNode.QueryTree().Only(ctx)
		if err != nil {
			return err
		}
		if tree.Status != st.TreeStatusPending {
			logger.Info("Expected tree status to be pending", "status", tree.Status)
			continue
		}
		if _, ok := confirmedTxHashSet[[32]byte(tree.BaseTxid)]; !ok {
			logger.Debug("Base txid not found in confirmed txids", "base_txid", hex.EncodeToString(tree.BaseTxid))
			for txid := range confirmedTxHashSet {
				logger.Debug("confirmed txid", "txid", hex.EncodeToString(txid[:]))
			}
			continue
		}

		_, err = dbTx.Tree.UpdateOne(tree).
			SetStatus(st.TreeStatusAvailable).
			Save(ctx)
		if err != nil {
			return err
		}

		treeNodes, err := tree.QueryNodes().All(ctx)
		if err != nil {
			return err
		}
		for _, treeNode := range treeNodes {
			if treeNode.Status != st.TreeNodeStatusCreating {
				logger.Debug("Tree node is not in creating status", "node", treeNode.ID)
				continue
			}
			if len(treeNode.RawRefundTx) > 0 {
				tx, err := common.TxFromRawTxBytes(treeNode.RawRefundTx)
				if err != nil {
					return err
				}
				if !tx.HasWitness() {
					logger.Debug("Tree node has not been signed", "node", treeNode.ID)
					continue
				}
				treeNode, err = dbTx.TreeNode.UpdateOne(treeNode).
					SetStatus(st.TreeNodeStatusAvailable).
					Save(ctx)
				if err != nil {
					return err
				}
			} else {
				_, err = dbTx.TreeNode.UpdateOne(treeNode).
					SetStatus(st.TreeNodeStatusSplitted).
					Save(ctx)
				if err != nil {
					return err
				}
			}
		}
	}

	logger.Info("Finished handling block", "height", blockHeight)
	blockHeightProcessingTimeHistogram.Record(ctx, time.Since(start).Milliseconds(), metric.WithAttributes(
		attribute.String("network", network.String()),
	))
	return nil
}

func storeStaticDeposits(ctx context.Context, dbTx *ent.Tx, creditedAddresses []string, addressToUtxoMap map[string][]AddressDepositUtxo, network common.Network, blockHeight int64) error {
	logger := logging.GetLoggerFromContext(ctx)

	staticDepositAddresses, err := dbTx.DepositAddress.Query().
		Where(depositaddress.IsStaticEQ(true)).
		Where(depositaddress.AddressIn(creditedAddresses...)).
		All(ctx)
	if err != nil {
		return err
	}

	for _, address := range staticDepositAddresses {
		if utxos, ok := addressToUtxoMap[address.Address]; ok {
			for _, utxo := range utxos {
				txidBytes, err := hex.DecodeString(utxo.tx.TxID())
				if err != nil {
					return fmt.Errorf("unable to decode txid for a new utxo: %w", err)
				}
				err = dbTx.Utxo.Create().
					SetTxid(txidBytes).
					SetVout(utxo.idx).
					SetAmount(utxo.amount).
					SetPkScript(utxo.tx.TxOut[utxo.idx].PkScript).
					SetNetwork(common.SchemaNetwork(network)).
					SetBlockHeight(blockHeight).
					SetDepositAddress(address).
					OnConflictColumns("network", "txid", "vout").
					UpdateNewValues().
					Exec(ctx)
				if err != nil {
					return fmt.Errorf("unable to store a new utxo: %w", err)
				}
				logger.Debug("Stored an L1 utxo to a static deposit address", "address", address.Address, "txid", hex.EncodeToString(txidBytes), "amount", utxo.amount)
			}
		}
	}
	return nil
}

func tweakKeysForCoopExit(ctx context.Context, coopExit *ent.CooperativeExit, blockHeight int64) error {
	logger := logging.GetLoggerFromContext(ctx)
	transfer, err := coopExit.QueryTransfer().ForUpdate().Only(ctx)
	if err != nil {
		return fmt.Errorf("failed to query transfer: %w", err)
	}

	if transfer.ID.String() == "01981232-ad72-7cc0-bd76-0ea293cf501f" {
		logger.Info("skipping transfer", "transfer_id", transfer.ID)
		return nil
	}

	if transfer.Status == st.TransferStatusSenderKeyTweaked {
		logger.Info("Transfer already tweaked, skipping", "transfer_id", transfer.ID)
		return nil
	}

	if transfer.Status != st.TransferStatusSenderInitiatedCoordinator && transfer.Status != st.TransferStatusSenderKeyTweakPending {
		return fmt.Errorf("transfer is not in the expected status for key tweak: %s", transfer.Status)
	}

	transferLeaves, err := transfer.QueryTransferLeaves().All(ctx)
	if err != nil {
		return fmt.Errorf("failed to query transfer leaves: %w", err)
	}
	for _, leaf := range transferLeaves {
		keyTweak := &pb.SendLeafKeyTweak{}
		err := proto.Unmarshal(leaf.KeyTweak, keyTweak)
		if err != nil {
			return fmt.Errorf("failed to unmarshal key tweak: %w", err)
		}
		treeNode, err := leaf.QueryLeaf().Only(ctx)
		if err != nil {
			return fmt.Errorf("failed to query leaf: %w", err)
		}
		treeNodeUpdate, err := helper.TweakLeafKeyUpdate(ctx, treeNode, keyTweak)
		if err != nil {
			return fmt.Errorf("failed to tweak leaf key: %w", err)
		}
		err = treeNodeUpdate.Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to update tree node: %w", err)
		}
		_, err = leaf.Update().SetKeyTweak(nil).Save(ctx)
		if err != nil {
			return fmt.Errorf("failed to clear key tweak: %w", err)
		}
	}

	_, err = transfer.Update().SetStatus(st.TransferStatusSenderKeyTweaked).Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to update transfer status: %w", err)
	}

	logger.Info("Successfully tweaked key for coop exit transaction.", "txId", coopExit.ExitTxid, "blockHeight", blockHeight)
	return nil
}
