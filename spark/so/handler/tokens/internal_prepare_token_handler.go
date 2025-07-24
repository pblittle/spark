package tokens

import (
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/lightsparkdev/spark/so/lrc20"
	"github.com/lightsparkdev/spark/so/protoconverter"

	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"
	tokeninternalpb "github.com/lightsparkdev/spark/proto/spark_token_internal"

	"github.com/lightsparkdev/spark/so/tokens"

	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/logging"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/utils"
)

type InternalPrepareTokenHandler struct {
	config           *so.Config
	lrc20Client      *lrc20.Client
	enablePreemption bool
}

func NewInternalPrepareTokenHandler(config *so.Config, client *lrc20.Client) *InternalPrepareTokenHandler {
	return &InternalPrepareTokenHandler{
		config:           config,
		lrc20Client:      client,
		enablePreemption: false,
	}
}

func NewInternalPrepareTokenHandlerWithPreemption(config *so.Config, client *lrc20.Client) *InternalPrepareTokenHandler {
	return &InternalPrepareTokenHandler{
		config:           config,
		lrc20Client:      client,
		enablePreemption: true,
	}
}

func (h *InternalPrepareTokenHandler) PrepareTokenTransactionInternal(ctx context.Context, req *tokeninternalpb.PrepareTransactionRequest) (*tokeninternalpb.PrepareTransactionResponse, error) {
	logger := logging.GetLoggerFromContext(ctx)

	ctx, span := tracer.Start(ctx, "InternalPrepareTokenHandler.PrepareTokenTransactionInternal", getTokenTransactionAttributes(req.FinalTokenTransaction))
	defer span.End()
	partialTransactionHash, err := utils.HashTokenTransaction(req.FinalTokenTransaction, true)
	if err != nil {
		return nil, tokens.FormatErrorWithTransactionProto("failed to compute transaction hash", req.FinalTokenTransaction, err)
	}

	logger.Info("Starting token transaction", "partial_transaction_hash", hex.EncodeToString(partialTransactionHash), "keyshare_ids", req.KeyshareIds, "expiry_time", req.FinalTokenTransaction.ExpiryTime.String(), "final_token_transaction", logging.FormatProto("final_token_transaction", req.FinalTokenTransaction))

	expectedRevocationPublicKeys, err := h.validateAndReserveKeyshares(ctx, req.KeyshareIds, req.FinalTokenTransaction)
	if err != nil {
		return nil, err
	}

	db, err := ent.GetDbFromContext(ctx)
	if err != nil {
		return nil, err
	}
	expectedCreationEntityPublicKey, err := ent.GetEntityDkgKeyPublicKey(ctx, db.Client())
	if err != nil {
		return nil, err
	}

	err = validateFinalTokenTransaction(h.config, req.FinalTokenTransaction, req.TokenTransactionSignatures, expectedRevocationPublicKeys, expectedCreationEntityPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid final token transaction %s: %w", logging.FormatProto("final_token_transaction", req.FinalTokenTransaction), err)
	}

	txType, err := utils.InferTokenTransactionType(req.FinalTokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to check token transaction type: %w", err)
	}

	var inputTtxos []*ent.TokenOutput
	switch txType {
	case utils.TokenTransactionTypeCreate:
		err = validateIssuerSignature(req.FinalTokenTransaction, req.TokenTransactionSignatures, req.FinalTokenTransaction.GetCreateInput().GetIssuerPublicKey())
		if err != nil {
			return nil, fmt.Errorf("failed to validate create token transaction signature  %s: %w", logging.FormatProto("final_token_transaction", req.FinalTokenTransaction), err)
		}
		err = validateIssuerTokenNotAlreadyCreated(ctx, req.FinalTokenTransaction)
		if err != nil {
			return nil, err
		}
	case utils.TokenTransactionTypeMint:
		err = validateIssuerSignature(req.FinalTokenTransaction, req.TokenTransactionSignatures, req.FinalTokenTransaction.GetMintInput().GetIssuerPublicKey())
		if err != nil {
			return nil, fmt.Errorf("failed to validate mint token transaction signature %s: %w", logging.FormatProto("final_token_transaction", req.FinalTokenTransaction), err)
		}
		tokenMetadata, err := ent.GetTokenMetadataForTokenTransaction(ctx, req.FinalTokenTransaction)
		if err != nil {
			return nil, err
		}

		// When disconnecting LRC20, we must have token metadata
		if h.config.Token.DisconnectLRC20Node && tokenMetadata == nil {
			return nil, tokens.FormatErrorWithTransactionProto("minting not allowed because a created token was not found", req.FinalTokenTransaction,
				fmt.Errorf("no tokencreate entity found for token"))
		}

		// Enforce max supply if disconnecting LRC20 or if we have a token create entry in the DB
		if h.config.Token.DisconnectLRC20Node || tokenMetadata != nil {
			err = tokens.ValidateMintDoesNotExceedMaxSupply(ctx, req.FinalTokenTransaction)
			if err != nil {
				return nil, err
			}
		}
	case utils.TokenTransactionTypeTransfer:
		inputTtxos, err = ent.FetchAndLockTokenInputs(ctx, req.FinalTokenTransaction.GetTransferInput().GetOutputsToSpend())
		if err != nil {
			return nil, tokens.FormatErrorWithTransactionProto("failed to fetch outputs to spend", req.FinalTokenTransaction, err)
		}
		if len(inputTtxos) != len(req.FinalTokenTransaction.GetTransferInput().GetOutputsToSpend()) {
			return nil, tokens.FormatErrorWithTransactionProto("failed to fetch all leaves to spend", req.FinalTokenTransaction,
				fmt.Errorf("failed to fetch all leaves to spend: got %d leaves, expected %d", len(inputTtxos), len(req.FinalTokenTransaction.GetTransferInput().GetOutputsToSpend())))
		}

		err = validateTransferTokenTransactionUsingPreviousTransactionData(ctx, h.enablePreemption, req.FinalTokenTransaction, req.TokenTransactionSignatures, inputTtxos, h.config.Lrc20Configs[req.FinalTokenTransaction.Network.String()].TransactionExpiryDuration)
		if err != nil {
			return nil, fmt.Errorf("error validating transfer using previous output data %s: %w", logging.FormatProto("final_token_transaction", req.FinalTokenTransaction), err)
		}
		if h.enablePreemption && anyTtxosHaveSpentTransactions(inputTtxos) {
			if err := preemptOrRejectTransactionsWithInputEnts(ctx, req.FinalTokenTransaction, inputTtxos); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("token transaction type unknown")
	}

	sparkTokenTransaction, err := protoconverter.SparkTokenTransactionFromTokenProto(req.FinalTokenTransaction)
	if err != nil {
		return nil, tokens.FormatErrorWithTransactionProto("failed to convert token transaction", req.FinalTokenTransaction, err)
	}

	if !h.config.Token.DisconnectLRC20Node {
		logger.Info("Verifying token transaction with LRC20 node")
		err = h.lrc20Client.VerifySparkTx(ctx, sparkTokenTransaction)
		if err != nil {
			return nil, tokens.FormatErrorWithTransactionProto("failed to verify token transaction with LRC20 node", req.FinalTokenTransaction, err)
		}
		logger.Info("Token transaction verified with LRC20 node")
	}
	// Save the token transaction, created output ents, and update the outputs to spend.
	_, err = ent.CreateStartedTransactionEntities(ctx, req.FinalTokenTransaction, req.TokenTransactionSignatures, req.KeyshareIds, inputTtxos, req.CoordinatorPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to save token transaction and output ents %s: %w", logging.FormatProto("final_token_transaction", req.FinalTokenTransaction), err)
	}

	return &tokeninternalpb.PrepareTransactionResponse{}, nil
}

func anyTtxosHaveSpentTransactions(ttxos []*ent.TokenOutput) bool {
	for _, ttxo := range ttxos {
		if ttxo.Edges.OutputSpentTokenTransaction != nil {
			return true
		}
	}
	return false
}

// validateAndReserveKeyshares parses keyshare IDs, checks for duplicates, marks them as used, and returns expected revocation public keys
func (h *InternalPrepareTokenHandler) validateAndReserveKeyshares(ctx context.Context, keyshareIDs []string, finalTokenTransaction *tokenpb.TokenTransaction) ([][]byte, error) {
	logger := logging.GetLoggerFromContext(ctx)
	keyshareUUIDs := make([]uuid.UUID, len(keyshareIDs))
	// Ensure that the coordinator SO did not pass duplicate keyshare UUIDs for different outputs.
	seenUUIDs := make(map[uuid.UUID]bool)
	for i, id := range keyshareIDs {
		keyshareUUID, err := uuid.Parse(id)
		if err != nil {
			return nil, tokens.FormatErrorWithTransactionProto("failed to parse keyshare ID", finalTokenTransaction, err)
		}
		if seenUUIDs[keyshareUUID] {
			return nil, tokens.FormatErrorWithTransactionProto("duplicate keyshare UUID found", finalTokenTransaction, fmt.Errorf("duplicate keyshare UUID found: %s", keyshareUUID))
		}
		seenUUIDs[keyshareUUID] = true
		keyshareUUIDs[i] = keyshareUUID
	}
	logger.Info("Marking keyshares as used")
	keysharesMap, err := ent.MarkSigningKeysharesAsUsed(ctx, h.config, keyshareUUIDs)
	if err != nil {
		return nil, tokens.FormatErrorWithTransactionProto("failed to mark keyshares as used", finalTokenTransaction, err)
	}
	logger.Info("Keyshares marked as used")
	expectedRevocationPublicKeys := make([][]byte, len(keyshareIDs))
	for i, id := range keyshareUUIDs {
		keyshare, ok := keysharesMap[id]
		if !ok {
			return nil, tokens.FormatErrorWithTransactionProto("keyshare ID not found", finalTokenTransaction, fmt.Errorf("keyshare ID not found: %s", id))
		}
		expectedRevocationPublicKeys[i] = keyshare.PublicKey
	}
	return expectedRevocationPublicKeys, nil
}

// validateOperatorSpecificSignatures validates the signatures in the request against the transaction hash
// and verifies that the number of signatures matches the expected count based on transaction type
func validateOperatorSpecificSignatures(identityPublicKey []byte, operatorSpecificSignatures []*pb.OperatorSpecificOwnerSignature, tokenTransaction *ent.TokenTransaction) error {
	if len(tokenTransaction.Edges.SpentOutput) > 0 {
		return validateTransferOperatorSpecificSignatures(identityPublicKey, operatorSpecificSignatures, tokenTransaction)
	}
	return validateIssuerOperatorSpecificSignatures(identityPublicKey, operatorSpecificSignatures, tokenTransaction)
}

// validateTransferOperatorSpecificSignatures validates signatures for transfer transactions
func validateTransferOperatorSpecificSignatures(identityPublicKey []byte, operatorSpecificSignatures []*pb.OperatorSpecificOwnerSignature, tokenTransaction *ent.TokenTransaction) error {
	if len(operatorSpecificSignatures) != len(tokenTransaction.Edges.SpentOutput) {
		return tokens.FormatErrorWithTransactionEnt(
			fmt.Sprintf("expected %d signatures for transfer (one per input), but got %d",
				len(tokenTransaction.Edges.SpentOutput), len(operatorSpecificSignatures)),
			tokenTransaction, nil)
	}
	numInputs := len(tokenTransaction.Edges.SpentOutput)
	signaturesByIndex := make([]*pb.OperatorSpecificOwnerSignature, numInputs)

	// Sort signatures according to index position
	for _, sig := range operatorSpecificSignatures {
		index := int(sig.OwnerSignature.InputIndex)
		if index < 0 || index >= numInputs {
			return tokens.FormatErrorWithTransactionEnt(
				fmt.Sprintf(tokens.ErrInputIndexOutOfRange, index, numInputs-1),
				tokenTransaction, nil)
		}

		if signaturesByIndex[index] != nil {
			return tokens.FormatErrorWithTransactionEnt(
				fmt.Sprintf("duplicate signature for input index %d", index),
				tokenTransaction, nil)
		}

		signaturesByIndex[index] = sig
	}

	for i := 0; i < numInputs; i++ {
		if signaturesByIndex[i] == nil {
			return tokens.FormatErrorWithTransactionEnt(
				fmt.Sprintf("missing signature for input index %d", i),
				tokenTransaction, nil)
		}
	}

	// Sort spent outputs by their index
	spentOutputs := slices.SortedFunc(slices.Values(tokenTransaction.Edges.SpentOutput), func(a, b *ent.TokenOutput) int {
		return cmp.Compare(a.SpentTransactionInputVout, b.SpentTransactionInputVout)
	})

	// Validate each signature against its corresponding output
	for i, sig := range signaturesByIndex {
		payloadHash, err := utils.HashOperatorSpecificTokenTransactionSignablePayload(sig.Payload)
		if err != nil {
			return fmt.Errorf("%s: %w", tokens.ErrFailedToHashRevocationKeyshares, err)
		}

		if !bytes.Equal(sig.Payload.FinalTokenTransactionHash, tokenTransaction.FinalizedTokenTransactionHash) {
			return fmt.Errorf(tokens.ErrTransactionHashMismatch,
				sig.Payload.FinalTokenTransactionHash, tokenTransaction.FinalizedTokenTransactionHash)
		}

		if !bytes.Equal(sig.Payload.OperatorIdentityPublicKey, identityPublicKey) {
			return fmt.Errorf(tokens.ErrOperatorPublicKeyMismatch,
				sig.Payload.OperatorIdentityPublicKey, identityPublicKey)
		}

		output := spentOutputs[i]
		if err := utils.ValidateOwnershipSignature(
			sig.OwnerSignature.Signature,
			payloadHash,
			output.OwnerPublicKey,
		); err != nil {
			return tokens.FormatErrorWithTransactionEnt(tokens.ErrInvalidOwnerSignature, tokenTransaction, err)
		}
	}

	return nil
}

// validateIssuerOperatorSpecificSignatures validates signatures for mint and create transactions
func validateIssuerOperatorSpecificSignatures(identityPublicKey []byte, operatorSpecificSignatures []*pb.OperatorSpecificOwnerSignature, tokenTransaction *ent.TokenTransaction) error {
	if len(operatorSpecificSignatures) != 1 {
		return tokens.FormatErrorWithTransactionEnt(
			fmt.Sprintf("expected exactly 1 signature for mint/create, but got %d",
				len(operatorSpecificSignatures)),
			tokenTransaction, nil)
	}

	var issuerPublicKey []byte
	if tokenTransaction.Edges.Mint != nil {
		issuerPublicKey = tokenTransaction.Edges.Mint.IssuerPublicKey
	} else if tokenTransaction.Edges.Create != nil {
		issuerPublicKey = tokenTransaction.Edges.Create.IssuerPublicKey
	} else {
		return tokens.FormatErrorWithTransactionEnt(
			"neither mint nor create record found in db, but expected one for this transaction",
			tokenTransaction, nil)
	}

	sig := operatorSpecificSignatures[0]

	// Validate the signature payload
	payloadHash, err := utils.HashOperatorSpecificTokenTransactionSignablePayload(sig.Payload)
	if err != nil {
		return fmt.Errorf("%s: %w", tokens.ErrFailedToHashRevocationKeyshares, err)
	}

	if !bytes.Equal(sig.Payload.FinalTokenTransactionHash, tokenTransaction.FinalizedTokenTransactionHash) {
		return fmt.Errorf(tokens.ErrTransactionHashMismatch,
			sig.Payload.FinalTokenTransactionHash, tokenTransaction.FinalizedTokenTransactionHash)
	}

	if len(sig.Payload.OperatorIdentityPublicKey) > 0 {
		if !bytes.Equal(sig.Payload.OperatorIdentityPublicKey, identityPublicKey) {
			return fmt.Errorf(tokens.ErrOperatorPublicKeyMismatch,
				sig.Payload.OperatorIdentityPublicKey, identityPublicKey)
		}
	}

	// Validate the signature using the issuer public key from the database
	if err := utils.ValidateOwnershipSignature(
		sig.OwnerSignature.Signature,
		payloadHash,
		issuerPublicKey,
	); err != nil {
		errorMsg := tokens.ErrInvalidIssuerSignature
		if tokenTransaction.Edges.Create != nil {
			errorMsg = "invalid issuer signature for create transaction"
		}
		return tokens.FormatErrorWithTransactionEnt(errorMsg, tokenTransaction, err)
	}

	return nil
}

// validateOutputs checks if all created outputs have the expected status
func validateOutputs(outputs []*ent.TokenOutput, expectedStatus st.TokenOutputStatus) []string {
	var invalidOutputs []string
	for i, output := range outputs {
		if output.Status != expectedStatus {
			invalidOutputs = append(invalidOutputs, fmt.Sprintf("output %d has invalid status %s, expected %s",
				i, output.Status, expectedStatus))
		}
	}
	return invalidOutputs
}

// validateInputs checks if all spent outputs have the expected status and aren't withdrawn
func validateInputs(outputs []*ent.TokenOutput, expectedStatus st.TokenOutputStatus) []string {
	var invalidOutputs []string
	for _, output := range outputs {
		if output.Status != expectedStatus {
			invalidOutputs = append(invalidOutputs, fmt.Sprintf("input %x has invalid status %s, expected %s",
				output.ID, output.Status, expectedStatus))
		}
		if output.ConfirmedWithdrawBlockHash != nil {
			invalidOutputs = append(invalidOutputs, fmt.Sprintf("input %x is already withdrawn",
				output.ID))
		}
	}
	return invalidOutputs
}

func validateIssuerSignature(
	tokenTransaction *tokenpb.TokenTransaction,
	signaturesWithIndex []*tokenpb.SignatureWithIndex,
	issuerPublicKey []byte,
) error {
	// Although this token transaction is final we pass in 'true' to generate the partial hash.
	partialTokenTransactionHash, err := utils.HashTokenTransaction(tokenTransaction, true)
	if err != nil {
		return tokens.FormatErrorWithTransactionProto("failed to hash token transaction", tokenTransaction, err)
	}

	err = utils.ValidateOwnershipSignature(signaturesWithIndex[0].Signature,
		partialTokenTransactionHash, issuerPublicKey)
	if err != nil {
		return tokens.FormatErrorWithTransactionProto("invalid issuer signature", tokenTransaction, err)
	}

	return nil
}

func validateTransferTokenTransactionUsingPreviousTransactionData(
	ctx context.Context,
	enablePreemption bool,
	tokenTransaction *tokenpb.TokenTransaction,
	signaturesWithIndex []*tokenpb.SignatureWithIndex,
	outputToSpendEnts []*ent.TokenOutput,
	v0DefaultTransactionExpiryDuration time.Duration,
) error {
	// All created outputs having the same token identifier is validated upstream, so only need to check against the first one.
	expectedTokenIdentifier := tokenTransaction.TokenOutputs[0].GetTokenIdentifier()
	if expectedTokenIdentifier != nil {
		// Validate that all spent outputs have the same token identifier
		for i, outputEnt := range outputToSpendEnts {
			if !bytes.Equal(outputEnt.TokenIdentifier, expectedTokenIdentifier) {
				return tokens.FormatErrorWithTransactionProto("token identifier mismatch", tokenTransaction, fmt.Errorf("output %d has different token identifier", i))
			}
		}
	} else {
		expectedTokenPubKey := tokenTransaction.TokenOutputs[0].GetTokenPublicKey()
		if expectedTokenPubKey == nil {
			return tokens.FormatErrorWithTransactionProto("invalid token public key", tokenTransaction, fmt.Errorf("token public key is required in outputs"))
		}
		// Validate that all spent outputs have the same token public key
		for i, outputEnt := range outputToSpendEnts {
			if !bytes.Equal(outputEnt.TokenPublicKey, expectedTokenPubKey) {
				return tokens.FormatErrorWithTransactionProto("token public key mismatch", tokenTransaction, fmt.Errorf("output %d has different token public key", i))
			}
		}
	}

	// TODO(DL-104): For now we allow the network to be nil to support old outputs. In the future we should require it to be set.
	for i, outputEnt := range outputToSpendEnts {
		if outputEnt.Network != ("") {
			entNetwork, err := outputEnt.Network.MarshalProto()
			if err != nil {
				return tokens.FormatErrorWithTransactionProto("failed to marshal network", tokenTransaction, err)
			}
			if entNetwork != tokenTransaction.Network {
				return tokens.FormatErrorWithTransactionProto("network mismatch", tokenTransaction, fmt.Errorf("output %d: %d != %d", i, entNetwork, tokenTransaction.Network))
			}
		}
	}
	// Validate token conservation in inputs + outputs.
	totalInputAmount := new(big.Int)
	for _, outputEnt := range outputToSpendEnts {
		inputAmount := new(big.Int).SetBytes(outputEnt.TokenAmount)
		totalInputAmount.Add(totalInputAmount, inputAmount)
	}
	totalOutputAmount := new(big.Int)
	for _, outputLeaf := range tokenTransaction.TokenOutputs {
		outputAmount := new(big.Int).SetBytes(outputLeaf.GetTokenAmount())
		totalOutputAmount.Add(totalOutputAmount, outputAmount)
	}
	if totalInputAmount.Cmp(totalOutputAmount) != 0 {
		return tokens.FormatErrorWithTransactionProto("token amount mismatch", tokenTransaction, fmt.Errorf("total input amount %s does not match total output amount %s", totalInputAmount.String(), totalOutputAmount.String()))
	}

	// Validate that the ownership signatures match the ownership public keys in the outputs to spend.
	// Although this token transaction is final we pass in 'true' to generate the partial hash.
	partialTokenTransactionHash, err := utils.HashTokenTransaction(tokenTransaction, true)
	if err != nil {
		return fmt.Errorf("failed to hash token transaction: %w", err)
	}

	ownerSignaturesByIndex := make(map[uint32]*tokenpb.SignatureWithIndex)
	for _, sig := range signaturesWithIndex {
		if sig == nil {
			return tokens.FormatErrorWithTransactionProto("invalid signature", tokenTransaction, fmt.Errorf("ownership signature cannot be nil"))
		}
		ownerSignaturesByIndex[sig.InputIndex] = sig
	}

	if len(signaturesWithIndex) != len(tokenTransaction.GetTransferInput().GetOutputsToSpend()) {
		return tokens.FormatErrorWithTransactionProto("signature count mismatch", tokenTransaction, fmt.Errorf("number of signatures must match number of outputs to spend"))
	}

	for i := range tokenTransaction.GetTransferInput().GetOutputsToSpend() {
		index := uint32(i)
		ownershipSignature, exists := ownerSignaturesByIndex[index]
		if !exists {
			return tokens.FormatErrorWithTransactionProto("missing signature", tokenTransaction, fmt.Errorf("missing owner signature for input index %d, indexes must be contiguous", index))
		}

		// Get the corresponding output entity (they are ordered outside of this block when they are fetched)
		outputEnt := outputToSpendEnts[i]
		if outputEnt == nil {
			return tokens.FormatErrorWithTransactionProto("missing output entity", tokenTransaction, fmt.Errorf("could not find output entity for output to spend at index %d", i))
		}

		err = utils.ValidateOwnershipSignature(ownershipSignature.Signature, partialTokenTransactionHash, outputEnt.OwnerPublicKey)
		if err != nil {
			return tokens.FormatErrorWithTransactionProto("invalid ownership signature", tokenTransaction, fmt.Errorf("invalid ownership signature for output %d: %w", i, err))
		}
		err = validateOutputIsSpendable(ctx, enablePreemption, i, outputEnt, tokenTransaction, v0DefaultTransactionExpiryDuration)
		if err != nil {
			return err
		}
	}

	return nil
}

// validateOutputIsSpendable checks if a output is eligible to be spent by verifying:
// 1. The output has an appropriate status (Created+Finalized or already marked as SpentStarted) OR was spent from an expired or pre-emptable transaction
// 2. The output hasn't been withdrawn already
func validateOutputIsSpendable(ctx context.Context, enablePreemption bool, index int, output *ent.TokenOutput, tokenTransaction *tokenpb.TokenTransaction, v0DefaultTransactionExpiryDuration time.Duration) error {
	if !isSpendableOutputStatus(output.Status) {
		spentTx := output.Edges.OutputSpentTokenTransaction
		if spentTx == nil {
			return fmt.Errorf("output %d cannot be spent: status must be %s or %s (was %s), or have been spent by an expired or pre-emptable transaction (none found)",
				index, st.TokenOutputStatusCreatedFinalized, st.TokenOutputStatusSpentStarted, output.Status)
		}
		if !spentTx.IsExpired(time.Now(), v0DefaultTransactionExpiryDuration) {
			canPreemptSpentTx := false
			if enablePreemption {
				cannotPreemptErr := preemptOrRejectTransaction(ctx, tokenTransaction, spentTx)
				canPreemptSpentTx = cannotPreemptErr == nil
			}
			if !canPreemptSpentTx {
				return fmt.Errorf("output %d cannot be spent: status must be %s or %s (was %s), or have been spent by an expired or pre-emptable transaction (transaction was not expired or pre-emptable, id: %s, final_hash: %s)",
					index, st.TokenOutputStatusCreatedFinalized, st.TokenOutputStatusSpentStarted, output.Status, spentTx.ID, hex.EncodeToString(spentTx.FinalizedTokenTransactionHash))
			}
		}
	}

	if output.ConfirmedWithdrawBlockHash != nil {
		return fmt.Errorf("output %d cannot be spent: already withdrawn", index)
	}

	return nil
}

// isSpendableOutputStatus checks if a output's status allows it to be spent.
func isSpendableOutputStatus(status st.TokenOutputStatus) bool {
	return status == st.TokenOutputStatusCreatedFinalized ||
		status == st.TokenOutputStatusSpentStarted
}

func validateFinalTokenTransaction(
	config *so.Config,
	tokenTransaction *tokenpb.TokenTransaction,
	signaturesWithIndex []*tokenpb.SignatureWithIndex,
	expectedRevocationPublicKeys [][]byte,
	expectedCreationEntityPublicKey []byte,
) error {
	network, err := common.NetworkFromProtoNetwork(tokenTransaction.Network)
	if err != nil {
		return fmt.Errorf("failed to get network from proto network: %w", err)
	}
	expectedBondSats := config.Lrc20Configs[network.String()].WithdrawBondSats
	expectedRelativeBlockLocktime := config.Lrc20Configs[network.String()].WithdrawRelativeBlockLocktime
	sparkOperatorsFromConfig := config.GetSigningOperatorList()

	validationConfig := &utils.FinalValidationConfig{
		ExpectedSparkOperators:             sparkOperatorsFromConfig,
		SupportedNetworks:                  config.SupportedNetworks,
		RequireTokenIdentifierForMints:     config.Token.RequireTokenIdentifierForMints,
		RequireTokenIdentifierForTransfers: config.Token.RequireTokenIdentifierForTransfers,
		ExpectedRevocationPublicKeys:       expectedRevocationPublicKeys,
		ExpectedBondSats:                   expectedBondSats,
		ExpectedRelativeBlockLocktime:      expectedRelativeBlockLocktime,
		ExpectedCreationEntityPublicKey:    expectedCreationEntityPublicKey,
	}

	err = utils.ValidateFinalTokenTransaction(
		tokenTransaction,
		signaturesWithIndex,
		validationConfig,
	)
	if err != nil {
		return fmt.Errorf("failed to validate final token transaction structure: %w", err)
	}

	return nil
}

func validateIssuerTokenNotAlreadyCreated(ctx context.Context, tokenTransaction *tokenpb.TokenTransaction) error {
	existingTokenCreateMetadata, err := ent.GetTokenMetadataForTokenTransaction(ctx, tokenTransaction)
	if err != nil {
		return tokens.FormatErrorWithTransactionProto("failed to search for existing token create entity", tokenTransaction, err)
	}
	if existingTokenCreateMetadata != nil {
		return tokens.FormatErrorWithTransactionProto("token already created for this issuer", tokenTransaction, fmt.Errorf("a token with this identifier has already been created"))
	}
	return nil
}
