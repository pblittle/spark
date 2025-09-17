package handler

import (
	"bytes"
	"context"
	dbSql "database/sql"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/lightsparkdev/spark/common/keys"
	"go.uber.org/zap"

	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	eciesgo "github.com/ecies/go/v2"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/logging"
	secretsharing "github.com/lightsparkdev/spark/common/secret_sharing"
	pbgossip "github.com/lightsparkdev/spark/proto/gossip"
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbspark "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/authz"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/ent/preimagerequest"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/sparkinvoice"
	enttransfer "github.com/lightsparkdev/spark/so/ent/transfer"
	enttransferleaf "github.com/lightsparkdev/spark/so/ent/transferleaf"
	"github.com/lightsparkdev/spark/so/ent/treenode"
	sparkerrors "github.com/lightsparkdev/spark/so/errors"
	"github.com/lightsparkdev/spark/so/helper"
	"github.com/lightsparkdev/spark/so/knobs"
	"google.golang.org/protobuf/proto"
)

// Validation constants to prevent resource exhaustion and DoS attacks
const (
	MaxLeavesToSend         = 1000              // Default fallback limit for leaf processing (can be overridden by knobs)
	MaxKeyTweakPackageSize  = 4 * 1024 * 1024   // 4MB limit for encrypted package
	MaxLeafIdLength         = 256               // Prevent extremely long leaf IDs
	MaxSecretShareSize      = 32                // Limit secret share size
	MaxSignatureSize        = 73                // Reasonable limit for ECDSA secp256k1 signatures
	MaxEstimatedMemoryUsage = 100 * 1024 * 1024 // 100MB limit for estimated memory usage
)

type TransferRole int

const (
	// TransferRoleCoordinator is the role of the coordinator in a transfer.
	// The coordinator is reponsible to make sure that the transfer key tweak is applied to all other participants,
	// if the participants agree to the key tweak.
	TransferRoleCoordinator TransferRole = iota
	// TransferRoleParticipant is the role of a participant in a transfer.
	TransferRoleParticipant
)

// BaseTransferHandler is the base transfer handler that is shared for internal and external transfer handlers.
type BaseTransferHandler struct {
	config *so.Config
}

// NewBaseTransferHandler creates a new BaseTransferHandler.
func NewBaseTransferHandler(config *so.Config) BaseTransferHandler {
	return BaseTransferHandler{
		config: config,
	}
}

func validateLeafRefundTxOutput(refundTx *wire.MsgTx, receiverIdentityPubKey keys.Public) error {
	if len(refundTx.TxOut) == 0 {
		return fmt.Errorf("refund tx must have at least 1 output")
	}
	recieverP2trScript, err := common.P2TRScriptFromPubKey(receiverIdentityPubKey)
	if err != nil {
		return fmt.Errorf("unable to generate p2tr script from receiver pubkey: %w", err)
	}
	if !bytes.Equal(recieverP2trScript, refundTx.TxOut[0].PkScript) {
		return fmt.Errorf("refund tx is expected to send to receiver identity pubkey")
	}
	return nil
}

func validateLeafRefundTxInput(refundTx *wire.MsgTx, oldSequence uint32, leafOutPoint *wire.OutPoint, expectedInputCount uint32) error {
	if len(refundTx.TxIn) == 0 {
		return fmt.Errorf("refund tx must have at least 1 input")
	}
	if refundTx.Version < 2 {
		return fmt.Errorf("refund tx must be v2 or above, got v%d", refundTx.Version)
	}
	if refundTx.TxIn[0].Sequence&(1<<31) != 0 {
		return fmt.Errorf("refund tx input 0 sequence must have bit 31 clear to enable relative locktime, got %d", refundTx.TxIn[0].Sequence)
	}
	if oldSequence&(1<<22) != 0 {
		return fmt.Errorf("old sequence must have bit 22 clear to enable block-based relative locktime, got %d", oldSequence)
	}
	if refundTx.TxIn[0].Sequence&(1<<22) != 0 {
		return fmt.Errorf("refund tx input 0 sequence must have bit 22 clear to enable block-based relative locktime, got %d", refundTx.TxIn[0].Sequence)
	}

	newTimeLock := refundTx.TxIn[0].Sequence & 0xFFFF
	oldTimeLock := oldSequence & 0xFFFF
	if newTimeLock+spark.TimeLockInterval > oldTimeLock {
		return fmt.Errorf("time lock on the new refund tx %d must be less than the old one %d", newTimeLock, oldTimeLock)
	}
	if len(refundTx.TxIn) != int(expectedInputCount) {
		return fmt.Errorf("refund tx should have %d inputs, but has %d", expectedInputCount, len(refundTx.TxIn))
	}
	if !refundTx.TxIn[0].PreviousOutPoint.Hash.IsEqual(&leafOutPoint.Hash) || refundTx.TxIn[0].PreviousOutPoint.Index != leafOutPoint.Index {
		return fmt.Errorf("unexpected input in refund tx")
	}
	return nil
}

func validateSendLeafRefundTxs(leaf *ent.TreeNode, rawTx []byte, directTx []byte, directFromCpfpRefundTx []byte, receiverIdentityPubKey keys.Public, expectedInputCount uint32, requireDirectTx bool) error {
	newCpfpRefundTx, err := common.TxFromRawTxBytes(rawTx)
	if err != nil {
		return fmt.Errorf("unable to load new cpfp refund tx: %w", err)
	}
	var newDirectRefundTx *wire.MsgTx
	var newDirectFromCpfpRefundTx *wire.MsgTx
	leafDirectOutPoint := wire.OutPoint{}
	leafDirectFromCpfpOutPoint := wire.OutPoint{}
	if len(directTx) > 0 && len(directFromCpfpRefundTx) > 0 && len(leaf.DirectTx) > 0 {
		var oldDirectRefundTxSequence uint32
		var oldDirectFromCpfpRefundTxSequence uint32
		newDirectRefundTx, err = common.TxFromRawTxBytes(directTx)
		if err != nil {
			return fmt.Errorf("unable to load new direct refund tx: %w", err)
		}
		newDirectFromCpfpRefundTx, err = common.TxFromRawTxBytes(directFromCpfpRefundTx)
		if err != nil {
			return fmt.Errorf("unable to load new direct from cpfprefund tx: %w", err)
		}
		if len(newDirectRefundTx.TxIn) == 0 {
			return fmt.Errorf("new direct refund tx has no inputs")
		}
		if len(newDirectFromCpfpRefundTx.TxIn) == 0 {
			return fmt.Errorf("new direct from cpfp refund tx has no inputs")

		}
		if len(leaf.DirectRefundTx) > 0 && len(leaf.DirectFromCpfpRefundTx) > 0 {
			oldDirectRefundTx, err := common.TxFromRawTxBytes(leaf.DirectRefundTx)
			if err != nil {
				return fmt.Errorf("unable to load old direct refund tx: %w", err)
			}
			oldDirectFromCpfpRefundTx, err := common.TxFromRawTxBytes(leaf.DirectFromCpfpRefundTx)
			if err != nil {
				return fmt.Errorf("unable to load old direct from cpfp refund tx: %w", err)
			}
			if len(oldDirectRefundTx.TxIn) == 0 {
				return fmt.Errorf("old direct refund tx has no inputs")
			}
			if len(oldDirectFromCpfpRefundTx.TxIn) == 0 {
				return fmt.Errorf("old direct from cpfp refund tx has no inputs")
			}
			oldDirectRefundTxIn := oldDirectRefundTx.TxIn[0]
			leafDirectOutPoint = wire.OutPoint{
				Hash:  oldDirectRefundTxIn.PreviousOutPoint.Hash,
				Index: oldDirectRefundTxIn.PreviousOutPoint.Index,
			}
			oldDirectFromCpfpRefundTxIn := oldDirectFromCpfpRefundTx.TxIn[0]
			leafDirectFromCpfpOutPoint = wire.OutPoint{
				Hash:  oldDirectFromCpfpRefundTxIn.PreviousOutPoint.Hash,
				Index: oldDirectFromCpfpRefundTxIn.PreviousOutPoint.Index,
			}
			oldDirectRefundTxSequence = oldDirectRefundTxIn.Sequence
			oldDirectFromCpfpRefundTxSequence = oldDirectFromCpfpRefundTxIn.Sequence
		} else {
			oldDirectRefundTxSequence = 0xFFFF
			oldDirectFromCpfpRefundTxSequence = 0xFFFF
			leafDirectOutPoint = wire.OutPoint{
				Hash:  newDirectRefundTx.TxIn[0].PreviousOutPoint.Hash,
				Index: newDirectRefundTx.TxIn[0].PreviousOutPoint.Index,
			}
			leafDirectFromCpfpOutPoint = wire.OutPoint{
				Hash:  newDirectFromCpfpRefundTx.TxIn[0].PreviousOutPoint.Hash,
				Index: newDirectFromCpfpRefundTx.TxIn[0].PreviousOutPoint.Index,
			}
		}

		err = validateLeafRefundTxInput(newDirectRefundTx, oldDirectRefundTxSequence, &leafDirectOutPoint, expectedInputCount)
		if err != nil {
			return fmt.Errorf("unable to validate direct refund tx inputs: %w", err)
		}
		err = validateLeafRefundTxInput(newDirectFromCpfpRefundTx, oldDirectFromCpfpRefundTxSequence, &leafDirectFromCpfpOutPoint, expectedInputCount)
		if err != nil {
			return fmt.Errorf("unable to validate direct from cpfp refund tx inputs: %w", err)
		}
		err = validateLeafRefundTxOutput(newDirectRefundTx, receiverIdentityPubKey)
		if err != nil {
			return fmt.Errorf("unable to validate direct refund tx output: %w", err)
		}
		err = validateLeafRefundTxOutput(newDirectFromCpfpRefundTx, receiverIdentityPubKey)
		if err != nil {
			return fmt.Errorf("unable to validate direct from cpfp refund tx output: %w", err)
		}
	} else if requireDirectTx && len(leaf.DirectTx) > 0 {
		return fmt.Errorf("DirectNodeTxSignature is required. Please upgrade to the latest SDK version")
	}

	oldCpfpRefundTx, err := common.TxFromRawTxBytes(leaf.RawRefundTx)
	if err != nil {
		return fmt.Errorf("unable to load old cpfp refund tx: %w", err)
	}
	if len(oldCpfpRefundTx.TxIn) == 0 {
		return fmt.Errorf("old cpfp refund tx has no inputs")
	}
	oldCpfpRefundTxIn := oldCpfpRefundTx.TxIn[0]
	leafCpfpOutPoint := wire.OutPoint{
		Hash:  oldCpfpRefundTxIn.PreviousOutPoint.Hash,
		Index: oldCpfpRefundTxIn.PreviousOutPoint.Index,
	}

	err = validateLeafRefundTxInput(newCpfpRefundTx, oldCpfpRefundTxIn.Sequence, &leafCpfpOutPoint, expectedInputCount)
	if err != nil {
		return fmt.Errorf("unable to validate cpfp refund tx inputs: %w", err)
	}

	err = validateLeafRefundTxOutput(newCpfpRefundTx, receiverIdentityPubKey)
	if err != nil {
		return fmt.Errorf("unable to validate cpfp refund tx output: %w", err)
	}
	return nil
}

func (h *BaseTransferHandler) createTransfer(
	ctx context.Context,
	transferID string,
	transferType st.TransferType,
	expiryTime time.Time,
	senderIdentityPubKey keys.Public,
	receiverIdentityPubKey keys.Public,
	leafCpfpRefundMap map[string][]byte,
	leafDirectRefundMap map[string][]byte,
	leafDirectFromCpfpRefundMap map[string][]byte,
	leafTweakMap map[string]*pbspark.SendLeafKeyTweak,
	role TransferRole,
	requireDirectTx bool,
	sparkInvoice string,
) (*ent.Transfer, map[string]*ent.TreeNode, error) {
	transferUUID, err := uuid.Parse(transferID)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse transfer_id as a uuid %s: %w", transferID, err)
	}

	if expiryTime.Unix() != 0 && expiryTime.Before(time.Now()) {
		return nil, nil, fmt.Errorf("invalid expiry_time %s: %w", expiryTime.String(), err)
	}

	var status st.TransferStatus
	if len(leafTweakMap) > 0 {
		if role == TransferRoleCoordinator {
			status = st.TransferStatusSenderInitiatedCoordinator
		} else {
			status = st.TransferStatusSenderKeyTweakPending
		}
	} else {
		status = st.TransferStatusSenderInitiated
	}

	db, err := ent.GetDbFromContext(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get database transaction: %w", err)
	}

	invoiceID := uuid.Nil
	//nolint:all
	if len(sparkInvoice) > 0 {
		// TODO: (CNT-493) Re-enable invoice functionality once spark address migration is complete
		return nil, nil, sparkerrors.UnimplementedErrorf("spark invoice support not implemented")
		invoiceID, err = createAndLockSparkInvoice(ctx, sparkInvoice)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to create and lock spark invoice: %w", err)
		}
	}

	transferCreate := db.Transfer.Create().
		SetID(transferUUID).
		SetSenderIdentityPubkey(senderIdentityPubKey).
		SetReceiverIdentityPubkey(receiverIdentityPubKey).
		SetStatus(status).
		SetTotalValue(0).
		SetExpiryTime(expiryTime).
		SetType(transferType)

	if len(sparkInvoice) > 0 && invoiceID != uuid.Nil {
		transferCreate = transferCreate.SetSparkInvoiceID(invoiceID)
	}

	transfer, err := transferCreate.Save(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create transfer: %w", err)
	}

	if len(leafCpfpRefundMap) == 0 {
		return nil, nil, sparkerrors.InvalidUserInputErrorf("must provide at least one leaf for transfer")
	}

	leaves, err := loadLeavesWithLock(ctx, db, leafCpfpRefundMap)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to load leaves: %w", err)
	}

	switch transferType {
	case st.TransferTypeCooperativeExit:
		err = h.validateCooperativeExitLeaves(ctx, transfer, leaves, leafCpfpRefundMap, leafDirectRefundMap, leafDirectFromCpfpRefundMap, receiverIdentityPubKey, requireDirectTx)
	case st.TransferTypeTransfer, st.TransferTypeSwap, st.TransferTypeCounterSwap:
		err = h.validateTransferLeaves(ctx, transfer, leaves, leafCpfpRefundMap, leafDirectRefundMap, leafDirectFromCpfpRefundMap, receiverIdentityPubKey, requireDirectTx)
	case st.TransferTypeUtxoSwap:
		err = h.validateUtxoSwapLeaves(ctx, transfer, leaves, leafCpfpRefundMap, leafDirectRefundMap, leafDirectFromCpfpRefundMap, receiverIdentityPubKey, requireDirectTx)
	case st.TransferTypePreimageSwap:
		err = h.validatePreimageSwapLeaves(ctx, transfer, leaves, leafCpfpRefundMap, leafDirectRefundMap, leafDirectFromCpfpRefundMap, receiverIdentityPubKey, requireDirectTx)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("unable to validate transfer leaves: %w", err)
	}

	err = createTransferLeaves(ctx, db, transfer, leaves, leafCpfpRefundMap, leafDirectRefundMap, leafDirectFromCpfpRefundMap, leafTweakMap)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create transfer leaves: %w", err)
	}

	err = setTotalTransferValue(ctx, db, transfer, leaves)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to update transfer total value: %w", err)
	}

	leaves, err = lockLeaves(ctx, db, leaves)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to lock leaves: %w", err)
	}

	leafMap := make(map[string]*ent.TreeNode)
	for _, leaf := range leaves {
		leafMap[leaf.ID.String()] = leaf
	}

	return transfer, leafMap, nil
}

func createAndLockSparkInvoice(ctx context.Context, sparkInvoice string) (uuid.UUID, error) {
	db, err := ent.GetDbFromContext(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("unable to get database transaction: %w", err)
	}
	decoded, err := common.ParseSparkInvoice(sparkInvoice)
	if err != nil {
		return uuid.Nil, fmt.Errorf("unable to parse spark invoice: %w", err)
	}
	var expiry *time.Time
	if decoded.ExpiryTime != nil && decoded.ExpiryTime.IsValid() {
		t := decoded.ExpiryTime.AsTime()
		expiry = &t
	}
	err = db.SparkInvoice.Create().
		SetID(decoded.Id).
		SetSparkInvoice(sparkInvoice).
		SetReceiverPublicKey(decoded.ReceiverPublicKey.Serialize()).
		SetNillableExpiryTime(expiry).
		OnConflictColumns(sparkinvoice.FieldID).
		DoNothing().
		Exec(ctx)
	// Do not update an invoice if one already exists with the same ID.
	// Ent Create expects a returning row, but ON CONFLICT DO NOTHING returns 0 rows.
	// As 0 rows is expected in conflict cases, ignore dbSql.ErrNoRows.
	if err != nil && !errors.Is(err, dbSql.ErrNoRows) {
		return uuid.Nil, fmt.Errorf("unable to create spark invoice: %w", err)
	}

	storedInvoice, err := db.SparkInvoice.
		Query().
		Where(sparkinvoice.IDEQ(decoded.Id)).
		ForUpdate().
		Only(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("lock invoice: %w", err)
	}
	if storedInvoice.SparkInvoice != sparkInvoice {
		return uuid.Nil, sparkerrors.InvalidUserInputErrorf("Conflicting invoices found for id: %s. Decoded request invoice: %s", storedInvoice.ID.String(), sparkInvoice)
	}

	// Check if an existing transfer is in flight or paid with this invoice.
	paidOrInFlightTransferExists, err := db.Transfer.
		Query().
		Where(
			enttransfer.HasSparkInvoiceWith(sparkinvoice.IDEQ(storedInvoice.ID)),
			enttransfer.StatusNotIn(
				// If an invoice has an edge to a transfer in any other state
				// that invoice is considered paid or in flight. Do not pay it again.
				st.TransferStatusReturned,
			),
		).
		Exist(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to query transfer: %w", err)
	}
	if paidOrInFlightTransferExists {
		return uuid.Nil, sparkerrors.InvalidUserInputErrorf("invoice has already been paid")
	}
	return storedInvoice.ID, nil
}

func loadLeavesWithLock(ctx context.Context, db *ent.Tx, leafRefundMap map[string][]byte) ([]*ent.TreeNode, error) {
	leafUUIDs := make([]uuid.UUID, 0, len(leafRefundMap))
	for leafID := range leafRefundMap {
		leafUUID, err := uuid.Parse(leafID)
		if err != nil {
			return nil, fmt.Errorf("unable to parse leaf_id %s: %w", leafID, err)
		}
		leafUUIDs = append(leafUUIDs, leafUUID)
	}

	leaves, err := db.TreeNode.Query().
		Where(treenode.IDIn(leafUUIDs...)).
		WithTree().
		ForUpdate().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to find leaves: %w", err)
	}
	if len(leaves) != len(leafRefundMap) {
		return nil, fmt.Errorf("some leaves not found")
	}

	var network *st.Network
	for _, leaf := range leaves {
		tree := leaf.Edges.Tree
		if tree == nil {
			return nil, fmt.Errorf("unable to find tree for leaf %s", leaf.ID)
		}
		if network == nil {
			network = &tree.Network
		} else if tree.Network != *network {
			return nil, fmt.Errorf("leaves sent for transfer must be on the same network")
		}
	}

	return leaves, nil
}

func (h *BaseTransferHandler) validateCooperativeExitLeaves(ctx context.Context, transfer *ent.Transfer, leaves []*ent.TreeNode, leafCpfpRefundMap map[string][]byte, leafDirectRefundMap map[string][]byte, leafDirectFromCpfpRefundMap map[string][]byte, receiverIdentityPublicKey keys.Public, requireDirectTx bool) error {
	for _, leaf := range leaves {
		directRefundTx := leafDirectRefundMap[leaf.ID.String()]
		intermediateDirectFromCpfpRefundTx := leafDirectFromCpfpRefundMap[leaf.ID.String()]

		rawRefundTx, exist := leafCpfpRefundMap[leaf.ID.String()]
		if !exist {
			return fmt.Errorf("leaf %s not found in cpfp refund map", leaf.ID)
		}

		err := validateSendLeafRefundTxs(leaf, rawRefundTx, directRefundTx, intermediateDirectFromCpfpRefundTx, receiverIdentityPublicKey, 2, requireDirectTx)
		if err != nil {
			return fmt.Errorf("unable to validate refund tx for leaf %s: %w", leaf.ID, err)
		}
		err = h.leafAvailableToTransfer(ctx, leaf, transfer)
		if err != nil {
			return fmt.Errorf("unable to validate leaf %s: %w", leaf.ID, err)
		}
	}
	return nil
}

func (h *BaseTransferHandler) validatePreimageSwapLeaves(
	ctx context.Context,
	transfer *ent.Transfer,
	leaves []*ent.TreeNode,
	leafCpfpRefundMap map[string][]byte,
	leafDirectRefundMap map[string][]byte,
	leafDirectFromCpfpRefundMap map[string][]byte,
	receiverIdentityPublicKey keys.Public,
	requireDirectTx bool,
) error {
	for _, leaf := range leaves {
		err := h.leafAvailableToTransfer(ctx, leaf, transfer)
		if err != nil {
			return fmt.Errorf("unable to validate leaf %s: %w", leaf.ID, err)
		}
	}
	return nil
}

func (h *BaseTransferHandler) validateUtxoSwapLeaves(
	ctx context.Context,
	transfer *ent.Transfer,
	leaves []*ent.TreeNode,
	leafCpfpRefundMap map[string][]byte,
	leafDirectRefundMap map[string][]byte,
	leafDirectFromCpfpRefundMap map[string][]byte,
	receiverIdentityPublicKey keys.Public,
	requireDirectTx bool,
) error {
	for _, leaf := range leaves {
		directRefundTx := leafDirectRefundMap[leaf.ID.String()]
		intermediateDirectFromCpfpRefundTx := leafDirectFromCpfpRefundMap[leaf.ID.String()]

		rawRefundTx, exist := leafCpfpRefundMap[leaf.ID.String()]
		if !exist {
			return fmt.Errorf("leaf %s not found in cpfp refund map", leaf.ID)
		}

		err := validateSendLeafRefundTxs(leaf, rawRefundTx, directRefundTx, intermediateDirectFromCpfpRefundTx, receiverIdentityPublicKey, 1, requireDirectTx)
		if err != nil {
			return fmt.Errorf("unable to validate refund tx for leaf %s: %w", leaf.ID, err)
		}
		err = h.leafAvailableToTransfer(ctx, leaf, transfer)
		if err != nil {
			return fmt.Errorf("unable to validate leaf %s: %w", leaf.ID, err)
		}
	}
	return nil
}

func (h *BaseTransferHandler) validateTransferLeaves(
	ctx context.Context,
	transfer *ent.Transfer,
	leaves []*ent.TreeNode,
	leafCpfpRefundMap map[string][]byte,
	leafDirectRefundMap map[string][]byte,
	leafDirectFromCpfpRefundMap map[string][]byte,
	receiverIdentityPublicKey keys.Public,
	requireDirectTx bool,
) error {
	for _, leaf := range leaves {
		// TODO(LIG-7719) reinstate direct tx validation once sync_transfer_refunds job has been added.
		rawRefundTx, exist := leafCpfpRefundMap[leaf.ID.String()]
		if !exist {
			return fmt.Errorf("leaf %s not found in cpfp refund map", leaf.ID)
		}

		err := validateSendLeafRefundTxs(leaf, rawRefundTx, nil, nil, receiverIdentityPublicKey, 1, false)
		if err != nil {
			return fmt.Errorf("unable to validate refund tx for leaf %s: %w", leaf.ID, err)
		}
		err = h.leafAvailableToTransfer(ctx, leaf, transfer)
		if err != nil {
			return fmt.Errorf("unable to validate leaf %s: %w", leaf.ID, err)
		}
	}
	return nil
}

func (h *BaseTransferHandler) leafAvailableToTransfer(ctx context.Context, leaf *ent.TreeNode, transfer *ent.Transfer) error {
	if leaf.Status != st.TreeNodeStatusAvailable {
		if leaf.Status == st.TreeNodeStatusTransferLocked {
			transferLeaves, err := transfer.QueryTransferLeaves().Where(
				enttransferleaf.HasLeafWith(treenode.IDEQ(leaf.ID)),
			).WithTransfer().All(ctx)
			if err != nil {
				return fmt.Errorf("unable to find transfer leaf for leaf %v: %w", leaf.ID, err)
			}
			now := time.Now()
			for _, transferLeaf := range transferLeaves {
				if transferLeaf.Edges.Transfer.Status == st.TransferStatusSenderInitiated && transferLeaf.Edges.Transfer.ExpiryTime.Before(now) {
					err := h.CancelTransferInternal(ctx, transfer.ID.String())
					if err != nil {
						return fmt.Errorf("unable to cancel transfer: %w", err)
					}
				}
			}
		}
		return fmt.Errorf("leaf %v is not available to transfer, status: %s", leaf.ID, leaf.Status)
	}
	ownerIDPubKey, err := keys.ParsePublicKey(leaf.OwnerIdentityPubkey)
	if err != nil {
		return fmt.Errorf("unable to parse leaf owner identity public key: %w", err)
	}
	if !ownerIDPubKey.Equals(transfer.SenderIdentityPubkey) {
		return fmt.Errorf("leaf %v is not owned by sender", leaf.ID)
	}
	return nil
}

func createTransferLeaves(
	ctx context.Context,
	db *ent.Tx,
	transfer *ent.Transfer,
	leaves []*ent.TreeNode,
	cpfpLeafRefundMap map[string][]byte,
	directLeafRefundMap map[string][]byte,
	directFromCpfpLeafRefundMap map[string][]byte,
	leafTweakMap map[string]*pbspark.SendLeafKeyTweak,
) error {
	mutators := make([]*ent.TransferLeafCreate, 0, len(leaves))
	for _, leaf := range leaves {
		rawRefundTx := cpfpLeafRefundMap[leaf.ID.String()]
		directRefundTx := directLeafRefundMap[leaf.ID.String()]
		intermediateDirectFromCpfpRefundTx := directFromCpfpLeafRefundMap[leaf.ID.String()]
		mutator := db.TransferLeaf.Create().
			SetTransfer(transfer).
			SetLeaf(leaf).
			SetPreviousRefundTx(leaf.RawRefundTx).
			SetPreviousDirectRefundTx(leaf.DirectRefundTx).
			SetIntermediateRefundTx(rawRefundTx).
			SetIntermediateDirectRefundTx(directRefundTx).
			SetIntermediateDirectFromCpfpRefundTx(intermediateDirectFromCpfpRefundTx)
		if leafTweakMap != nil {
			leafTweak, ok := leafTweakMap[leaf.ID.String()]
			if ok {
				leafTweakBinary, err := proto.Marshal(leafTweak)
				if err != nil {
					return fmt.Errorf("unable to marshal leaf tweak: %w", err)
				}
				mutator = mutator.SetKeyTweak(leafTweakBinary)
			}
		}
		mutators = append(mutators, mutator)
	}
	if len(mutators) > 0 {
		_, err := db.TransferLeaf.CreateBulk(mutators...).Save(ctx)
		if err != nil {
			return fmt.Errorf("unable to create transfer leaf: %w", err)
		}
	}
	return nil
}

func setTotalTransferValue(ctx context.Context, db *ent.Tx, transfer *ent.Transfer, leaves []*ent.TreeNode) error {
	totalAmount := getTotalTransferValue(leaves)
	_, err := db.Transfer.UpdateOne(transfer).SetTotalValue(totalAmount).Save(ctx)
	if err != nil {
		return fmt.Errorf("unable to update transfer total value: %w", err)
	}
	return nil
}

func getTotalTransferValue(leaves []*ent.TreeNode) uint64 {
	totalAmount := uint64(0)
	for _, leaf := range leaves {
		totalAmount += leaf.Value
	}
	return totalAmount
}

func lockLeaves(ctx context.Context, db *ent.Tx, leaves []*ent.TreeNode) ([]*ent.TreeNode, error) {
	ids := make([]uuid.UUID, len(leaves))
	for i, leaf := range leaves {
		ids[i] = leaf.ID
	}

	err := db.TreeNode.Update().
		Where(treenode.IDIn(ids...)).
		SetStatus(st.TreeNodeStatusTransferLocked).
		Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to update leaf statuses: %w", err)
	}

	updatedLeaves, err := db.TreeNode.Query().
		Where(treenode.IDIn(ids...)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch updated leaves: %w", err)
	}

	if len(updatedLeaves) != len(leaves) {
		return nil, fmt.Errorf("some leaves not found")
	}
	return updatedLeaves, nil
}

func (h *BaseTransferHandler) CancelTransfer(ctx context.Context, req *pbspark.CancelTransferRequest) (*pbspark.CancelTransferResponse, error) {
	reqSenderIDPubKey, err := keys.ParsePublicKey(req.SenderIdentityPublicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to parse sender identity public key: %w", err)
	}
	if err := authz.EnforceSessionIdentityPublicKeyMatches(ctx, h.config, reqSenderIDPubKey); err != nil {
		return nil, err
	}

	transfer, err := h.loadTransferNoUpdate(ctx, req.TransferId)
	if err != nil {
		logger := logging.GetLoggerFromContext(ctx)
		logger.Sugar().Info("Transfer %s not found", req.TransferId)
		return &pbspark.CancelTransferResponse{}, nil
	}
	if !transfer.SenderIdentityPubkey.Equals(reqSenderIDPubKey) {
		return nil, fmt.Errorf("only sender is eligible to cancel the transfer %s", req.TransferId)
	}

	if transfer.Status != st.TransferStatusSenderInitiated &&
		transfer.Status != st.TransferStatusSenderKeyTweakPending &&
		transfer.Status != st.TransferStatusSenderInitiatedCoordinator &&
		transfer.Status != st.TransferStatusReturned {
		return nil, fmt.Errorf("transfer %s is expected to be at status TransferStatusSenderInitiated, TransferStatusSenderKeyTweakPending or TransferStatusSenderInitiatedCoordinator or TransferStatusReturned but %s found", transfer.ID.String(), transfer.Status)
	}

	// The expiry time is only checked for coordinator SO because the creation time of each SO could be different.
	if transfer.Status != st.TransferStatusSenderInitiated && transfer.ExpiryTime.After(time.Now()) {
		return nil, fmt.Errorf("transfer %s has not expired, expires at %s", req.TransferId, transfer.ExpiryTime.String())
	}

	// Check to see if preimage has already been shared before cancelling
	// Only check external requests as there currently exists some internal
	// use case for cancelling transfers after preimage share, e.g. preimage
	// is incorrect

	db, err := ent.GetDbFromContext(ctx)
	if err != nil {
		return nil, err
	}

	preimageRequest, err := db.PreimageRequest.Query().Where(preimagerequest.HasTransfersWith(enttransfer.ID(transfer.ID))).Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return nil, fmt.Errorf("encountered error when fetching preimage request for transfer id %s: %w", req.TransferId, err)
	}
	if preimageRequest != nil && preimageRequest.Status == st.PreimageRequestStatusPreimageShared {
		return nil, sparkerrors.FailedPreconditionErrorf("Cannot cancel an invoice whose preimage has already been revealed")
	}

	err = h.CreateCancelTransferGossipMessage(ctx, req.TransferId)
	if err != nil {
		return nil, fmt.Errorf("unable to create and send gossip message: %w", err)
	}
	return &pbspark.CancelTransferResponse{}, nil
}

func (h *BaseTransferHandler) CreateCancelTransferGossipMessage(ctx context.Context, transferID string) error {
	selection := helper.OperatorSelection{Option: helper.OperatorSelectionOptionExcludeSelf}
	participants, err := selection.OperatorIdentifierList(h.config)
	if err != nil {
		return fmt.Errorf("unable to get operator list: %w", err)
	}
	sendGossipHandler := NewSendGossipHandler(h.config)
	_, err = sendGossipHandler.CreateAndSendGossipMessage(ctx, &pbgossip.GossipMessage{
		Message: &pbgossip.GossipMessage_CancelTransfer{
			CancelTransfer: &pbgossip.GossipMessageCancelTransfer{
				TransferId: transferID,
			},
		},
	}, participants)
	if err != nil {
		return fmt.Errorf("unable to create and send gossip message: %w", err)
	}
	return nil
}

func (h *BaseTransferHandler) CreateRollbackTransferGossipMessage(ctx context.Context, transferID string) error {
	selection := helper.OperatorSelection{Option: helper.OperatorSelectionOptionExcludeSelf}
	participants, err := selection.OperatorIdentifierList(h.config)
	if err != nil {
		return fmt.Errorf("unable to get operator list: %w", err)
	}
	sendGossipHandler := NewSendGossipHandler(h.config)
	_, err = sendGossipHandler.CreateAndSendGossipMessage(ctx, &pbgossip.GossipMessage{
		Message: &pbgossip.GossipMessage_RollbackTransfer{
			RollbackTransfer: &pbgossip.GossipMessageRollbackTransfer{
				TransferId: transferID,
			},
		},
	}, participants)
	if err != nil {
		return fmt.Errorf("unable to create and send gossip message: %w", err)
	}
	return nil
}

func (h *BaseTransferHandler) CancelTransferInternal(ctx context.Context, transferID string) error {
	transfer, err := h.loadTransferForUpdate(ctx, transferID)
	if err != nil {
		return fmt.Errorf("unable to load transfer: %w", err)
	}

	return h.executeCancelTransfer(ctx, transfer)
}

func (h *BaseTransferHandler) executeCancelTransfer(ctx context.Context, transfer *ent.Transfer) error {
	// Don't error if the transfer is already returned.
	logger := logging.GetLoggerFromContext(ctx)
	if transfer.Status == st.TransferStatusReturned {
		logger.Sugar().Infof("Transfer %s already returned", transfer.ID)
		return nil
	}
	// Prevent cancellation of transfers in terminal or advanced states
	if transfer.Status == st.TransferStatusCompleted ||
		transfer.Status == st.TransferStatusExpired {
		return fmt.Errorf("transfer %s is already in terminal state %s and cannot be cancelled", transfer.ID.String(), transfer.Status)
	}
	// Only allow cancellation from early states
	if transfer.Status != st.TransferStatusSenderInitiated &&
		transfer.Status != st.TransferStatusSenderKeyTweakPending &&
		transfer.Status != st.TransferStatusSenderInitiatedCoordinator {
		return fmt.Errorf("transfer %s cannot be cancelled from status %s", transfer.ID.String(), transfer.Status)
	}

	var err error
	transfer, err = transfer.Update().SetStatus(st.TransferStatusReturned).Save(ctx)
	if err != nil {
		return fmt.Errorf("unable to update transfer status: %w", err)
	}

	err = h.cancelTransferUnlockLeaves(ctx, transfer)
	if err != nil {
		return fmt.Errorf("unable to unlock leaves in the transfer: %w", err)
	}

	err = h.cancelTransferCancelRequest(ctx, transfer)
	if err != nil {
		return fmt.Errorf("unable to cancel associated request: %w", err)
	}

	return nil
}

func (h *BaseTransferHandler) RollbackTransfer(ctx context.Context, transferID string) error {
	logger := logging.GetLoggerFromContext(ctx)

	transfer, err := h.loadTransferForUpdate(ctx, transferID)
	if err != nil {
		return fmt.Errorf("unable to load transfer %s: %w", transferID, err)
	}

	if transfer.Status == st.TransferStatusSenderInitiated {
		logger.Sugar().Infof("Transfer %s already in sender initiated state", transferID)
		return nil
	} else if transfer.Status != st.TransferStatusSenderKeyTweakPending && transfer.Status != st.TransferStatusSenderInitiatedCoordinator {
		return fmt.Errorf("expected transfer %s to be in sender key tweak pending state, instead got %s", transferID, transfer.Status)
	}

	// Get all transfer leaves
	transferLeaves, err := transfer.QueryTransferLeaves().All(ctx)
	if err != nil {
		return fmt.Errorf("unable to get leaves for transfer %s: %w", transferID, err)
	}

	// Clear key tweak on each transfer leaf
	for _, transferLeaf := range transferLeaves {
		_, err = transferLeaf.Update().
			ClearKeyTweak().
			ClearSenderKeyTweakProof().
			Save(ctx)
		if err != nil {
			return fmt.Errorf("unable to clear key tweak from transfer leaf %s: %w", transferLeaf.ID.String(), err)
		}
	}

	// Update transfer status to sender initiated
	transfer, err = transfer.Update().SetStatus(st.TransferStatusSenderInitiated).Save(ctx)
	if err != nil {
		return fmt.Errorf("unable to update status for transfer %s: %w", transferID, err)
	}

	return nil
}

func (h *BaseTransferHandler) cancelTransferUnlockLeaves(ctx context.Context, transfer *ent.Transfer) error {
	transferLeaves, err := transfer.QueryTransferLeaves().All(ctx)
	if err != nil {
		return fmt.Errorf("unable to get transfer leaves: %w", err)
	}

	for _, leaf := range transferLeaves {
		treeNode, err := leaf.QueryLeaf().Only(ctx)
		if err != nil {
			return fmt.Errorf("unable to get tree node: %w", err)
		}
		_, err = treeNode.Update().SetStatus(st.TreeNodeStatusAvailable).Save(ctx)
		if err != nil {
			return fmt.Errorf("unable to update tree node status: %w", err)
		}
	}
	return nil
}

func (h *BaseTransferHandler) cancelTransferCancelRequest(ctx context.Context, transfer *ent.Transfer) error {
	if transfer.Type == st.TransferTypePreimageSwap {
		db, err := ent.GetDbFromContext(ctx)
		if err != nil {
			return err
		}

		preimageRequest, err := db.PreimageRequest.Query().Where(preimagerequest.HasTransfersWith(enttransfer.ID(transfer.ID))).Only(ctx)
		if err != nil || preimageRequest == nil {
			return fmt.Errorf("cannot find preimage request for transfer %s", transfer.ID.String())
		}
		err = preimageRequest.Update().SetStatus(st.PreimageRequestStatusReturned).Exec(ctx)
		if err != nil {
			return fmt.Errorf("unable to update preimage request status: %w", err)
		}
	}
	return nil
}

func (h *BaseTransferHandler) loadTransferForUpdate(ctx context.Context, transferID string, opts ...sql.LockOption) (*ent.Transfer, error) {
	transferUUID, err := uuid.Parse(transferID)
	if err != nil {
		return nil, fmt.Errorf("unable to parse transfer_id as a uuid %s: %w", transferID, err)
	}

	db, err := ent.GetDbFromContext(ctx)
	if err != nil {
		return nil, err
	}

	transfer, err := db.Transfer.Query().Where(enttransfer.ID(transferUUID)).ForUpdate(opts...).Only(ctx)
	if err != nil || transfer == nil {
		return nil, fmt.Errorf("unable to find transfer %s: %w", transferID, err)
	}
	return transfer, nil
}

func (h *BaseTransferHandler) loadTransferNoUpdate(ctx context.Context, transferID string) (*ent.Transfer, error) {
	transferUUID, err := uuid.Parse(transferID)
	if err != nil {
		return nil, fmt.Errorf("unable to parse transfer_id as a uuid %s: %w", transferID, err)
	}

	db, err := ent.GetDbFromContext(ctx)
	if err != nil {
		return nil, err
	}

	transfer, err := db.Transfer.Query().Where(enttransfer.ID(transferUUID)).Only(ctx)
	if err != nil || transfer == nil {
		return nil, fmt.Errorf("unable to find transfer %s: %w", transferID, err)
	}
	return transfer, nil
}

// ValidateTransferPackage validates the transfer package, to ensure the key tweaks are valid.
func (h *BaseTransferHandler) ValidateTransferPackage(ctx context.Context, transferID string, req *pbspark.TransferPackage, senderIdentityPubKey keys.Public) (map[string]*pbspark.SendLeafKeyTweak, error) {
	// If the transfer package is nil, we don't need to validate it.
	if req == nil {
		return nil, nil
	}

	if len(req.KeyTweakPackage) == 0 {
		return nil, fmt.Errorf("key tweak package is empty")
	}
	// Get the transfer limit from knobs if available
	// This allows runtime configuration of transfer limits without code changes
	// If KnobSoTransferLimit is set to 0, it uses the default MaxLeavesToSend constant
	transferLimit := MaxLeavesToSend // Default fallback
	knobService := knobs.GetKnobsService(ctx)
	if knobService != nil {
		knobLimit := knobService.GetValue(knobs.KnobSoTransferLimit, 0)
		if knobLimit > 0 {
			transferLimit = int(knobLimit)
		}
	}

	// Input size and count validation - prevent resource exhaustion
	if len(req.LeavesToSend) > transferLimit {
		return nil, fmt.Errorf("too many leaves to send: %d (max: %d)", len(req.LeavesToSend), transferLimit)
	}

	if len(req.DirectLeavesToSend) > transferLimit {
		return nil, fmt.Errorf("too many direct leaves to send: %d (max: %d)", len(req.DirectLeavesToSend), transferLimit)
	}

	if len(req.DirectFromCpfpLeavesToSend) > transferLimit {
		return nil, fmt.Errorf("too many direct from cpfp leaves to send: %d (max: %d)", len(req.DirectFromCpfpLeavesToSend), transferLimit)
	}

	// Validate key tweak package size
	totalSize := 0
	for _, ciphertext := range req.KeyTweakPackage {
		totalSize += len(ciphertext)
	}
	if totalSize > MaxKeyTweakPackageSize {
		return nil, fmt.Errorf("key tweak package too large: %d bytes (max: %d)", totalSize, MaxKeyTweakPackageSize)
	}

	// Validate leaf IDs in leaves_to_send
	for _, leaf := range req.LeavesToSend {
		_, err := uuid.Parse(leaf.LeafId)
		if err != nil {
			return nil, fmt.Errorf("unable to parse leaf_id as a uuid %s: %w", leaf.LeafId, err)
		}
	}

	// Validate leaf IDs in direct_leaves_to_send
	for _, leaf := range req.DirectLeavesToSend {
		_, err := uuid.Parse(leaf.LeafId)
		if err != nil {
			return nil, fmt.Errorf("unable to parse direct_leaves_to_send leaf_id as a uuid %s: %w", leaf.LeafId, err)
		}
	}

	// Validate leaf IDs in direct_from_cpfp_leaves_to_send
	for _, leaf := range req.DirectFromCpfpLeavesToSend {
		_, err := uuid.Parse(leaf.LeafId)
		if err != nil {
			return nil, fmt.Errorf("unable to parse direct_from_cpfp_leaves_to_send leaf_id as a uuid %s: %w", leaf.LeafId, err)
		}
	}

	// Signature validation - prevent replay/DoS
	if len(req.UserSignature) == 0 {
		return nil, fmt.Errorf("user signature cannot be empty")
	}

	if len(req.UserSignature) > MaxSignatureSize {
		return nil, fmt.Errorf("user signature too large: %d bytes (max: %d)", len(req.UserSignature), MaxSignatureSize)
	}

	// Decrypt the key tweaks
	leafTweaksCipherText := req.KeyTweakPackage[h.config.Identifier]
	if leafTweaksCipherText == nil {
		return nil, fmt.Errorf("no key tweaks found for SO %s", h.config.Identifier)
	}

	// Encrypted data validation - prevent decryption attacks
	if len(leafTweaksCipherText) == 0 {
		return nil, fmt.Errorf("encrypted key tweaks cannot be empty")
	}

	if len(leafTweaksCipherText) > MaxKeyTweakPackageSize {
		return nil, fmt.Errorf("encrypted key tweaks too large: %d bytes (max: %d)", len(leafTweaksCipherText), MaxKeyTweakPackageSize)
	}

	decryptionPrivateKey := eciesgo.NewPrivateKeyFromBytes(h.config.IdentityPrivateKey.Serialize())
	leafTweaksBinary, err := eciesgo.Decrypt(decryptionPrivateKey, leafTweaksCipherText)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key tweaks: %w", err)
	}

	leafTweaks := &pbspark.SendLeafKeyTweaks{}
	err = proto.Unmarshal(leafTweaksBinary, leafTweaks)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal key tweaks: %w", err)
	}

	// Memory usage validation - prevent OOM
	totalLeafCount := len(leafTweaks.LeavesToSend)
	if totalLeafCount > transferLimit {
		return nil, fmt.Errorf("too many leaves in key tweaks: %d (max: %d)", totalLeafCount, transferLimit)
	}

	// This should equal the number of SOs
	maxPubkeySharesTweakCount := len(h.config.GetSigningOperatorList())
	maxProofsCount := int(h.config.Threshold)

	// Estimate memory usage for the map
	estimatedMemory := totalLeafCount * (MaxLeafIdLength + MaxSecretShareSize + maxProofsCount*33 + maxPubkeySharesTweakCount*33)
	if estimatedMemory > MaxEstimatedMemoryUsage {
		return nil, fmt.Errorf("estimated memory usage too high: %d bytes (max: %d)", estimatedMemory, MaxEstimatedMemoryUsage)
	}

	leafTweaksMap := make(map[string]*pbspark.SendLeafKeyTweak)
	for _, leafTweak := range leafTweaks.LeavesToSend {
		// Validate leaf ID in key tweaks
		_, err := uuid.Parse(leafTweak.LeafId)
		if err != nil {
			return nil, fmt.Errorf("unable to parse key tweaks leaf_id as a uuid %s: %w", leafTweak.LeafId, err)
		}

		// Validate secret share size
		if len(leafTweak.SecretShareTweak.SecretShare) > MaxSecretShareSize {
			return nil, fmt.Errorf("secret share too large: %d bytes (max: %d)", len(leafTweak.SecretShareTweak.SecretShare), MaxSecretShareSize)
		}

		// Validate proofs count
		if len(leafTweak.SecretShareTweak.Proofs) > maxProofsCount {
			return nil, fmt.Errorf("too many proofs: %d (max: %d)", len(leafTweak.SecretShareTweak.Proofs), maxProofsCount)
		}

		// Validate pubkey shares count
		if len(leafTweak.PubkeySharesTweak) > maxPubkeySharesTweakCount {
			return nil, fmt.Errorf("too many pubkey shares: %d (max: %d)", len(leafTweak.PubkeySharesTweak), maxPubkeySharesTweakCount)
		}

		leafTweaksMap[leafTweak.LeafId] = leafTweak
	}

	transferIDUUID, err := uuid.Parse(transferID)
	if err != nil {
		return nil, fmt.Errorf("unable to parse transfer_id as a uuid %s: %w", transferID, err)
	}
	payloadToVerify := common.GetTransferPackageSigningPayload(transferIDUUID, req)

	if err := common.VerifyECDSASignature(senderIdentityPubKey, req.UserSignature, payloadToVerify); err != nil {
		return nil, fmt.Errorf("unable to verify user signature: %w", err)
	}

	for _, leafTweak := range leafTweaksMap {
		err := secretsharing.ValidateShare(
			&secretsharing.VerifiableSecretShare{
				SecretShare: secretsharing.SecretShare{
					FieldModulus: secp256k1.S256().N,
					Threshold:    int(h.config.Threshold),
					Index:        big.NewInt(int64(h.config.Index + 1)),
					Share:        new(big.Int).SetBytes(leafTweak.SecretShareTweak.SecretShare),
				},
				Proofs: leafTweak.SecretShareTweak.Proofs,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("unable to validate share: %w", err)
		}
		for _, pubkeyTweak := range leafTweak.PubkeySharesTweak {
			if _, err := keys.ParsePublicKey(pubkeyTweak); err != nil {
				return nil, fmt.Errorf("encountered error when parsing pubkey tweak: %w", err)
			}
		}
	}

	return leafTweaksMap, nil
}

func (h *BaseTransferHandler) validateKeyTweakProofs(ctx context.Context, transfer *ent.Transfer, senderKeyTweakProofs map[string]*pbspark.SecretProof) error {
	transferLeaves, err := transfer.QueryTransferLeaves().All(ctx)
	if err != nil {
		return fmt.Errorf("unable to get transfer leaves: %w", err)
	}

	for _, leaf := range transferLeaves {
		keyTweakProto := &pb.SendLeafKeyTweak{}
		err := proto.Unmarshal(leaf.KeyTweak, keyTweakProto)
		if err != nil {
			return fmt.Errorf("unable to unmarshal key tweak: %w", err)
		}

		keyTweakProof, ok := senderKeyTweakProofs[keyTweakProto.LeafId]
		if !ok {
			return fmt.Errorf("key tweak proof not found for leaf: %s", keyTweakProto.LeafId)
		}

		if !slices.EqualFunc(keyTweakProof.Proofs, keyTweakProto.SecretShareTweak.Proofs, bytes.Equal) {
			return fmt.Errorf("sender key tweak proof mismatch")
		}
	}
	return nil
}

func (h *BaseTransferHandler) CommitSenderKeyTweaks(ctx context.Context, transferID string, senderKeyTweakProofs map[string]*pbspark.SecretProof) (*ent.Transfer, error) {
	transfer, err := h.loadTransferForUpdate(ctx, transferID)
	if err != nil {
		return nil, fmt.Errorf("unable to load transfer: %w", err)
	}
	err = h.validateKeyTweakProofs(ctx, transfer, senderKeyTweakProofs)
	if err != nil {
		logger := logging.GetLoggerFromContext(ctx)
		logger.With(zap.Error(err)).Sugar().Errorf("Unable to validate key tweak proofs for transfer %s", transferID)
		return nil, err
	}
	return h.commitSenderKeyTweaks(ctx, transfer)
}

func (h *BaseTransferHandler) commitSenderKeyTweaks(ctx context.Context, transfer *ent.Transfer) (*ent.Transfer, error) {
	transfer, err := h.loadTransferForUpdate(ctx, transfer.ID.String())
	if err != nil {
		return nil, fmt.Errorf("unable to load transfer: %w", err)
	}
	logger := logging.GetLoggerFromContext(ctx)
	logger.Sugar().Infof("Checking commitSenderKeyTweaks for transfer %s (status: %s)", transfer.ID, transfer.Status)
	if transfer.Status == st.TransferStatusSenderKeyTweaked {
		return transfer, nil
	}
	if transfer.Status != st.TransferStatusSenderKeyTweakPending && transfer.Status != st.TransferStatusSenderInitiatedCoordinator {
		return nil, fmt.Errorf("transfer %s is not in sender key tweak pending status", transfer.ID.String())
	}
	transferLeaves, err := transfer.QueryTransferLeaves().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get transfer leaves: %w", err)
	}
	logger.Sugar().Infof("Beginning to tweak keys for transfer %s", transfer.ID)
	for _, leaf := range transferLeaves {
		keyTweak := &pbspark.SendLeafKeyTweak{}
		err := proto.Unmarshal(leaf.KeyTweak, keyTweak)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal key tweak: %w", err)
		}
		treeNode, err := leaf.QueryLeaf().Only(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to get tree node: %w", err)
		}
		logger.Sugar().Infof("Tweaking leaf %s for transfer %s", treeNode.ID, transfer.ID)
		treeNodeUpdate, err := helper.TweakLeafKeyUpdate(ctx, treeNode, keyTweak)
		if err != nil {
			return nil, fmt.Errorf("unable to tweak leaf key: %w", err)
		}
		err = treeNodeUpdate.Exec(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to update tree node: %w", err)
		}
		_, err = leaf.Update().
			SetKeyTweak(nil).
			SetSecretCipher(keyTweak.SecretCipher).
			SetSignature(keyTweak.Signature).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to update leaf key tweak: %w", err)
		}
	}
	transfer, err = transfer.Update().SetStatus(st.TransferStatusSenderKeyTweaked).Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to update transfer status: %w", err)
	}

	return transfer, nil
}
