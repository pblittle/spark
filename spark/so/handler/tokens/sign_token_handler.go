package tokens

import (
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/so/tokens"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/lightsparkdev/spark/common/logging"
	sparkpb "github.com/lightsparkdev/spark/proto/spark"
	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"
	tokeninternalpb "github.com/lightsparkdev/spark/proto/spark_token_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/authz"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/ent/predicate"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/tokenoutput"
	"github.com/lightsparkdev/spark/so/ent/tokentransaction"
	"github.com/lightsparkdev/spark/so/helper"
	"github.com/lightsparkdev/spark/so/protoconverter"
	"github.com/lightsparkdev/spark/so/utils"
)

const queryTokenOutputsWithPartialRevocationSecretSharesBatchSize = 50

type operatorSignaturesMap map[string][]byte

type SignTokenHandler struct {
	config *so.Config
}

// NewSignTokenHandler creates a new SignTokenHandler.
func NewSignTokenHandler(config *so.Config) *SignTokenHandler {
	return &SignTokenHandler{
		config: config,
	}
}

// SignTokenTransaction signs the token transaction with the operators private key.
// If it is a transfer it also fetches that operator's keyshare for each spent output and
// returns it to the wallet so it can finalize the transaction.
func (h *SignTokenHandler) SignTokenTransaction(
	ctx context.Context,
	req *sparkpb.SignTokenTransactionRequest,
) (*sparkpb.SignTokenTransactionResponse, error) {
	logger := logging.GetLoggerFromContext(ctx)

	if err := authz.EnforceSessionIdentityPublicKeyMatches(ctx, h.config, req.IdentityPublicKey); err != nil {
		return nil, err
	}

	tokenProtoTokenTransaction, err := protoconverter.TokenProtoFromSparkTokenTransaction(req.FinalTokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to convert token transaction to spark token transaction: %w", err)
	}

	finalTokenTransactionHash, err := utils.HashTokenTransaction(tokenProtoTokenTransaction, false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tokens.ErrFailedToHashFinalTransaction, err)
	}

	tokenTransaction, err := ent.FetchAndLockTokenTransactionData(ctx, tokenProtoTokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", tokens.ErrFailedToFetchTransaction, logging.FormatProto("final_token_transaction", req.FinalTokenTransaction), err)
	}

	internalSignTokenHandler := NewInternalSignTokenHandler(h.config)
	operatorSignature, err := internalSignTokenHandler.SignAndPersistTokenTransaction(ctx, tokenTransaction, finalTokenTransactionHash, req.OperatorSpecificSignatures)
	if err != nil {
		return nil, err
	}

	if tokenTransaction.Status == st.TokenTransactionStatusSigned {
		revocationKeyshares, err := h.getRevocationKeysharesForTokenTransaction(ctx, tokenTransaction)
		if err != nil {
			return nil, tokens.FormatErrorWithTransactionEnt(tokens.ErrFailedToGetRevocationKeyshares, tokenTransaction, err)
		}
		return &sparkpb.SignTokenTransactionResponse{
			SparkOperatorSignature: operatorSignature,
			RevocationKeyshares:    revocationKeyshares,
		}, nil
	}

	keyshares := make([]*ent.SigningKeyshare, len(tokenTransaction.Edges.SpentOutput))
	revocationKeyshares := make([]*sparkpb.KeyshareWithIndex, len(tokenTransaction.Edges.SpentOutput))
	for _, output := range tokenTransaction.Edges.SpentOutput {
		keyshare, err := output.QueryRevocationKeyshare().Only(ctx)
		if err != nil {
			logger.Info("Failed to get keyshare for output", "error", err)
			return nil, err
		}
		index := output.SpentTransactionInputVout
		keyshares[index] = keyshare
		revocationKeyshares[index] = &sparkpb.KeyshareWithIndex{
			InputIndex: uint32(index),
			Keyshare:   keyshare.SecretShare,
		}

		// Validate that the keyshare's public key is as expected.
		if !bytes.Equal(keyshare.PublicKey, output.WithdrawRevocationCommitment) {
			return nil, fmt.Errorf(
				"keyshare public key %x does not match output revocation commitment %x",
				keyshare.PublicKey,
				output.WithdrawRevocationCommitment,
			)
		}
	}

	// TODO: LRC20 client functionality removed
	// if !h.config.Token.DisconnectLRC20Node {
	//	operatorSignatureData := &pblrc20.SparkOperatorSignatureData{
	//		SparkOperatorSignature:    operatorSignature,
	//		OperatorIdentityPublicKey: secp256k1.PrivKeyFromBytes(h.config.IdentityPrivateKey).PubKey().SerializeCompressed(),
	//	}
	//	sparkSigReq := &pblrc20.SendSparkSignatureRequest{
	//		FinalTokenTransaction:      req.FinalTokenTransaction,
	//		OperatorSpecificSignatures: req.OperatorSpecificSignatures,
	//		OperatorSignatureData:      operatorSignatureData,
	//	}
	//	err = h.lrc20Client.SendSparkSignature(ctx, sparkSigReq)
	//	if err != nil {
	//		logger.Error("Failed to send transaction to LRC20 node", "error", err)
	//		return nil, err
	//	}
	// }
	return &sparkpb.SignTokenTransactionResponse{
		SparkOperatorSignature: operatorSignature,
		RevocationKeyshares:    revocationKeyshares,
	}, nil
}

func (h *SignTokenHandler) CommitTransaction(ctx context.Context, req *tokenpb.CommitTransactionRequest) (*tokenpb.CommitTransactionResponse, error) {
	logger := logging.GetLoggerFromContext(ctx)
	ctx, span := tracer.Start(ctx, "SignTokenHandler.CommitTransaction", getTokenTransactionAttributes(req.FinalTokenTransaction))
	defer span.End()

	if err := authz.EnforceSessionIdentityPublicKeyMatches(ctx, h.config, req.OwnerIdentityPublicKey); err != nil {
		return nil, fmt.Errorf("identity public key authentication failed: %w", err)
	}

	calculatedHash, err := utils.HashTokenTransaction(req.FinalTokenTransaction, false)
	if err != nil {
		return nil, fmt.Errorf("failed to hash final token transaction: %w", err)
	}
	if !bytes.Equal(calculatedHash, req.FinalTokenTransactionHash) {
		return nil, fmt.Errorf("transaction hash mismatch: expected %x, got %x", calculatedHash, req.FinalTokenTransactionHash)
	}

	tokenTransaction, err := ent.FetchAndLockTokenTransactionData(ctx, req.FinalTokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch transaction: %w", err)
	}

	if err := validateTokenTransactionForSigning(h.config, tokenTransaction); err != nil {
		return nil, tokens.FormatErrorWithTransactionEnt(err.Error(), tokenTransaction, err)
	}

	allOperators := helper.OperatorSelection{Option: helper.OperatorSelectionOptionAll}
	internalSignatures, err := helper.ExecuteTaskWithAllOperators(ctx, h.config, &allOperators,
		func(ctx context.Context, operator *so.SigningOperator) (*tokeninternalpb.SignTokenTransactionFromCoordinationResponse, error) {
			var foundOperatorSignatures *tokenpb.InputTtxoSignaturesPerOperator
			for _, operatorSignatures := range req.InputTtxoSignaturesPerOperator {
				if bytes.Equal(operatorSignatures.OperatorIdentityPublicKey, operator.IdentityPublicKey) {
					foundOperatorSignatures = operatorSignatures
					break
				}
			}
			if foundOperatorSignatures == nil {
				return nil, fmt.Errorf("no signatures found for operator %s: %w", operator.Identifier, err)
			}

			if operator.Identifier == h.config.Identifier {
				return h.localSignAndCommitTransaction(ctx, foundOperatorSignatures, req.FinalTokenTransactionHash, tokenTransaction)
			}

			conn, err := operator.NewGRPCConnection()
			if err != nil {
				return nil, fmt.Errorf("failed to connect to operator %s: %w", operator.Identifier, err)
			}
			defer conn.Close()
			client := tokeninternalpb.NewSparkTokenInternalServiceClient(conn)
			return client.SignTokenTransactionFromCoordination(ctx, &tokeninternalpb.SignTokenTransactionFromCoordinationRequest{
				FinalTokenTransaction:          req.FinalTokenTransaction,
				FinalTokenTransactionHash:      req.FinalTokenTransactionHash,
				InputTtxoSignaturesPerOperator: foundOperatorSignatures,
				OwnerIdentityPublicKey:         req.OwnerIdentityPublicKey,
			})
		},
	)
	if err != nil {
		return nil, tokens.FormatErrorWithTransactionEnt("failed to get signatures from operators", tokenTransaction, err)
	}

	signatures := make(operatorSignaturesMap)
	for operatorID, sig := range internalSignatures {
		signatures[operatorID] = sig.SparkOperatorSignature
	}

	internalSignTokenHandler := NewInternalSignTokenHandler(h.config)
	if err := internalSignTokenHandler.validateSignaturesPackageAndPersistPeerSignatures(ctx, signatures, tokenTransaction); err != nil {
		return nil, tokens.FormatErrorWithTransactionEnt("failed to validate signature package and persist peer signatures", tokenTransaction, err)
	}

	// TODO: LRC20 client functionality removed
	// if !h.config.Token.DisconnectLRC20Node {
	//	if err := h.sendSignaturesToLRC20Node(ctx, signatures[h.config.Identifier], req); err != nil {
	//		return nil, fmt.Errorf("failed to send signatures to LRC20 node: %w", err)
	//	}
	// }

	logger.Info("Successfully signed and committed token transaction",
		"transaction_hash", req.FinalTokenTransactionHash)

	if req.FinalTokenTransaction.GetTransferInput() != nil {
		if err := h.ExchangeRevocationSecretsAndFinalizeIfPossible(ctx, req.FinalTokenTransaction, internalSignatures, req.FinalTokenTransactionHash); err != nil {
			return nil, tokens.FormatErrorWithTransactionEnt("failed to exchange revocation secret shares and finalize if possible", tokenTransaction, err)
		}
	}

	return &tokenpb.CommitTransactionResponse{}, nil
}

func (h *SignTokenHandler) ExchangeRevocationSecretsAndFinalizeIfPossible(ctx context.Context, tokenTransactionProto *tokenpb.TokenTransaction, internalSignatures map[string]*tokeninternalpb.SignTokenTransactionFromCoordinationResponse, tokenTransactionhash []byte) error {
	response, err := h.exchangeRevocationSecretShares(ctx, internalSignatures, tokenTransactionProto, tokenTransactionhash)
	if err != nil {
		return fmt.Errorf("coordinator failed to exchange revocation secret shares with all other operators for token txHash: %x: %w", tokenTransactionhash, err)
	}

	// Collect the secret shares from all operators.
	var operatorShares []*tokeninternalpb.OperatorRevocationShares
	for _, exchangeResponse := range response {
		if exchangeResponse == nil {
			return fmt.Errorf("nil exchange response received from operator for token txHash: %x", tokenTransactionhash)
		}
		operatorShares = append(operatorShares, exchangeResponse.ReceivedOperatorShares...)
	}
	inputOperatorShareMap, err := buildInputOperatorShareMap(operatorShares)
	if err != nil {
		return fmt.Errorf("failed to build input operator share map for token txHash: %x: %w", tokenTransactionhash, err)
	}

	// Persist the secret shares from all operators.
	internalHandler := NewInternalSignTokenHandler(h.config)
	finalized, err := internalHandler.persistPartialRevocationSecretShares(ctx, inputOperatorShareMap, tokenTransactionhash)
	if err != nil {
		return fmt.Errorf("failed to persist partial revocation secret shares for token txHash: %x: %w", tokenTransactionhash, err)
	}
	if finalized {
		_, err := h.exchangeRevocationSecretShares(ctx, internalSignatures, tokenTransactionProto, tokenTransactionhash)
		if err != nil {
			return fmt.Errorf("failed to exchange revocation secret shares for token txHash after finalized: %x: %w", tokenTransactionhash, err)
		}
	}
	return nil
}

func (h *SignTokenHandler) exchangeRevocationSecretShares(ctx context.Context, allOperatorSignaturesResponse map[string]*tokeninternalpb.SignTokenTransactionFromCoordinationResponse, tokenTransaction *tokenpb.TokenTransaction, tokenTransactionHash []byte) (map[string]*tokeninternalpb.ExchangeRevocationSecretsSharesResponse, error) {
	// prepare the operator signatures package
	allOperatorSignaturesPackage := make([]*tokeninternalpb.OperatorTransactionSignature, 0, len(allOperatorSignaturesResponse))
	for identifier, sig := range allOperatorSignaturesResponse {
		allOperatorSignaturesPackage = append(allOperatorSignaturesPackage, &tokeninternalpb.OperatorTransactionSignature{
			OperatorIdentityPublicKey: h.config.SigningOperatorMap[identifier].IdentityPublicKey,
			Signature:                 sig.SparkOperatorSignature,
		})
	}

	revocationSecretShares, err := h.prepareRevocationSecretSharesForExchange(ctx, tokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare coordinator revocation secret shares for exchange: %w for token txHash: %x", err, tokenTransactionHash)
	}

	// exchange the revocation secret shares with all other operators
	opSelection := helper.OperatorSelection{Option: helper.OperatorSelectionOptionExcludeSelf}
	response, errorExchangingWithAllOperators := helper.ExecuteTaskWithAllOperators(ctx, h.config, &opSelection, func(ctx context.Context, operator *so.SigningOperator) (*tokeninternalpb.ExchangeRevocationSecretsSharesResponse, error) {
		conn, err := operator.NewGRPCConnection()
		if err != nil {
			return nil, fmt.Errorf("failed to connect to operator %s: %w for token txHash: %x", operator.Identifier, err, tokenTransactionHash)
		}
		defer conn.Close()
		client := tokeninternalpb.NewSparkTokenInternalServiceClient(conn)
		return client.ExchangeRevocationSecretsShares(ctx, &tokeninternalpb.ExchangeRevocationSecretsSharesRequest{
			FinalTokenTransaction:         tokenTransaction,
			FinalTokenTransactionHash:     tokenTransactionHash,
			OperatorTransactionSignatures: allOperatorSignaturesPackage,
			OperatorShares:                revocationSecretShares,
			OperatorIdentityPublicKey:     h.config.IdentityPublicKey(),
		})
	})

	// We have exchanged our secrets. Mark as revealed and start a new tx in context.
	tx, err := ent.GetDbFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get or create current tx for request: %w", err)
	}
	if _, err := tx.TokenTransaction.Update().
		Where(
			tokentransaction.StatusNEQ(st.TokenTransactionStatusFinalized),
			tokentransaction.FinalizedTokenTransactionHashEQ(tokenTransactionHash),
		).
		SetStatus(st.TokenTransactionStatusRevealed).
		Save(ctx); err != nil {
		return nil, fmt.Errorf("failed to update token transaction status to Revealed: %w for token txHash: %x", err, tokenTransactionHash)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit and replace transaction after exchanging revocation secret shares: %w for token txHash: %x", err, tokenTransactionHash)
	}

	// If there was an error exchanging with all operators, we will roll back to the revealed status.
	if errorExchangingWithAllOperators != nil {
		return nil, fmt.Errorf("1 failed to exchange revocation secret shares: %w for token txHash: %x", errorExchangingWithAllOperators, tokenTransactionHash)
	}

	return response, nil
}

func (h *SignTokenHandler) prepareRevocationSecretSharesForExchange(ctx context.Context, tokenTransaction *tokenpb.TokenTransaction) ([]*tokeninternalpb.OperatorRevocationShares, error) {
	db, err := ent.GetDbFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get or create current tx for request: %w", err)
	}

	outputsToSpend := tokenTransaction.GetTransferInput().GetOutputsToSpend()

	var matchOutputsToSpendPredicates []predicate.TokenOutput
	for _, outputToSpend := range outputsToSpend {
		if outputToSpend != nil {
			matchOutputsToSpendPredicates = append(matchOutputsToSpendPredicates,
				tokenoutput.And(
					tokenoutput.HasOutputCreatedTokenTransactionWith(
						tokentransaction.FinalizedTokenTransactionHashEQ(outputToSpend.GetPrevTokenTransactionHash()),
					),
					tokenoutput.CreatedTransactionOutputVout(int32(outputToSpend.GetPrevTokenTransactionVout())),
				),
			)
		}
	}

	const batchSize = queryTokenOutputsWithPartialRevocationSecretSharesBatchSize
	var outputsWithKeyShares []*ent.TokenOutput

	for i := 0; i < len(matchOutputsToSpendPredicates); i += batchSize {
		end := i + batchSize
		if end > len(matchOutputsToSpendPredicates) {
			end = len(matchOutputsToSpendPredicates)
		}
		batchPredicates := matchOutputsToSpendPredicates[i:end]
		batchOutputs, err := db.TokenOutput.Query().
			Where(tokenoutput.Or(batchPredicates...)).
			WithRevocationKeyshare().
			WithTokenPartialRevocationSecretShares().
			All(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to query TokenOutputs batch (%d-%d): %w", i, end-1, err)
		}

		outputsWithKeyShares = append(outputsWithKeyShares, batchOutputs...)
	}

	sharesToReturnMap := make(map[string]*tokeninternalpb.OperatorRevocationShares)

	coordinatorPubKeyStr := hex.EncodeToString(h.config.IdentityPublicKey())
	allOperatorPubkeys := make([]helper.OperatorIdentityPubkey, 0, len(h.config.SigningOperatorMap))
	for _, operator := range h.config.SigningOperatorMap {
		identityPubkey, err := helper.NewOperatorIdentityPubkey(operator.IdentityPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create operator identity public key: %w", err)
		}
		allOperatorPubkeys = append(allOperatorPubkeys, identityPubkey)
	}

	for _, identityPubkey := range allOperatorPubkeys {
		sharesToReturnMap[identityPubkey.String()] = &tokeninternalpb.OperatorRevocationShares{
			OperatorIdentityPublicKey: identityPubkey.Bytes(),
			Shares:                    make([]*tokeninternalpb.RevocationSecretShare, 0, len(tokenTransaction.GetTransferInput().GetOutputsToSpend())),
		}
	}

	for _, outputWithKeyShare := range outputsWithKeyShares {
		if keyshare := outputWithKeyShare.Edges.RevocationKeyshare; keyshare != nil {
			if operatorShares, exists := sharesToReturnMap[coordinatorPubKeyStr]; exists {
				operatorShares.Shares = append(operatorShares.Shares, &tokeninternalpb.RevocationSecretShare{
					InputTtxoId: outputWithKeyShare.ID.String(),
					SecretShare: keyshare.SecretShare,
				})
			}
		}
		if outputWithKeyShare.Edges.TokenPartialRevocationSecretShares != nil {
			for _, partialShare := range outputWithKeyShare.Edges.TokenPartialRevocationSecretShares {
				operatorKey := hex.EncodeToString(partialShare.OperatorIdentityPublicKey)
				if operatorShares, exists := sharesToReturnMap[operatorKey]; exists {
					operatorShares.Shares = append(operatorShares.Shares, &tokeninternalpb.RevocationSecretShare{
						InputTtxoId: outputWithKeyShare.ID.String(),
						SecretShare: partialShare.SecretShare,
					})
				}
			}
		}
	}

	operatorRevocationShares := make([]*tokeninternalpb.OperatorRevocationShares, 0, len(sharesToReturnMap))
	for _, operatorShares := range sharesToReturnMap {
		operatorRevocationShares = append(operatorRevocationShares, operatorShares)
	}

	return operatorRevocationShares, nil
}

func (h *SignTokenHandler) localSignAndCommitTransaction(
	ctx context.Context,
	foundOperatorSignatures *tokenpb.InputTtxoSignaturesPerOperator,
	finalTokenTransactionHash []byte,
	tokenTransaction *ent.TokenTransaction,
) (*tokeninternalpb.SignTokenTransactionFromCoordinationResponse, error) {
	operatorSpecificSignatures := convertTokenProtoSignaturesToOperatorSpecific(
		foundOperatorSignatures.TtxoSignatures,
		finalTokenTransactionHash,
		h.config.IdentityPublicKey(),
	)
	internalSignTokenHandler := NewInternalSignTokenHandler(h.config)
	sigBytes, err := internalSignTokenHandler.SignAndPersistTokenTransaction(ctx, tokenTransaction, finalTokenTransactionHash, operatorSpecificSignatures)
	if err != nil {
		return nil, err
	}
	return &tokeninternalpb.SignTokenTransactionFromCoordinationResponse{
		SparkOperatorSignature: sigBytes,
	}, nil
}

// getRevocationKeysharesForTokenTransaction retrieves the revocation keyshares for a token transaction
func (h *SignTokenHandler) getRevocationKeysharesForTokenTransaction(ctx context.Context, tokenTransaction *ent.TokenTransaction) ([]*sparkpb.KeyshareWithIndex, error) {
	spentOutputs := tokenTransaction.Edges.SpentOutput
	revocationKeyshares := make([]*sparkpb.KeyshareWithIndex, len(spentOutputs))
	for i, output := range spentOutputs {
		keyshare, err := output.QueryRevocationKeyshare().Only(ctx)
		if err != nil {
			return nil, tokens.FormatErrorWithTransactionEnt(tokens.ErrFailedToGetKeyshareForOutput, tokenTransaction, err)
		}
		// Validate that the keyshare's public key is as expected.
		if !bytes.Equal(keyshare.PublicKey, output.WithdrawRevocationCommitment) {
			return nil, tokens.FormatErrorWithTransactionEnt(
				fmt.Sprintf("%s: %x does not match %x",
					tokens.ErrRevocationKeyMismatch, keyshare.PublicKey, output.WithdrawRevocationCommitment),
				tokenTransaction, nil)
		}

		revocationKeyshares[i] = &sparkpb.KeyshareWithIndex{
			InputIndex: uint32(output.SpentTransactionInputVout),
			Keyshare:   keyshare.SecretShare,
		}
	}
	// Sort spent output keyshares by their index to ensure a consistent response
	slices.SortFunc(revocationKeyshares, func(a, b *sparkpb.KeyshareWithIndex) int {
		return cmp.Compare(a.InputIndex, b.InputIndex)
	})

	return revocationKeyshares, nil
}

func validateTokenTransactionForSigning(config *so.Config, tokenTransactionEnt *ent.TokenTransaction) error {
	if tokenTransactionEnt.Status != st.TokenTransactionStatusStarted &&
		tokenTransactionEnt.Status != st.TokenTransactionStatusSigned {
		return fmt.Errorf("signing failed because transaction is not in correct state, expected %s or %s, current status: %s", st.TokenTransactionStatusStarted, st.TokenTransactionStatusSigned, tokenTransactionEnt.Status)
	}

	// Get the network-specific transaction expiry duration
	schemaNetwork, err := tokenTransactionEnt.GetNetworkFromEdges()
	if err != nil {
		return fmt.Errorf("failed to get network from edges: %w", err)
	}
	network, err := common.NetworkFromSchemaNetwork(schemaNetwork)
	if err != nil {
		return fmt.Errorf("failed to get network from schema network: %w", err)
	}
	transactionV0ExpiryDuration := config.Lrc20Configs[network.String()].TransactionExpiryDuration

	if err := tokenTransactionEnt.ValidateNotExpired(transactionV0ExpiryDuration); err != nil {
		return err
	}
	return nil
}

// verifyOperatorSignatures verifies the signatures from each operator for a token transaction.
func verifyOperatorSignatures(
	signatures map[string][]byte,
	operatorMap map[string]*so.SigningOperator,
	finalTokenTransactionHash []byte,
) error {
	validateOperatorSignature := func(operatorID string, sigBytes []byte) error {
		operator, ok := operatorMap[operatorID]
		if !ok {
			return fmt.Errorf("operator %s not found in operator map", operatorID)
		}

		operatorPubKey, err := secp256k1.ParsePubKey(operator.IdentityPublicKey)
		if err != nil {
			return fmt.Errorf("failed to parse operator public key for operator %s: %w", operatorID, err)
		}

		operatorSig, err := ecdsa.ParseDERSignature(sigBytes)
		if err != nil {
			return fmt.Errorf("failed to parse operator signature for operator %s: %w", operatorID, err)
		}

		if !operatorSig.Verify(finalTokenTransactionHash, operatorPubKey) {
			return fmt.Errorf("invalid signature from operator %s", operatorID)
		}

		return nil
	}

	var errors []string
	for operatorID, sigBytes := range signatures {
		if err := validateOperatorSignature(operatorID, sigBytes); err != nil {
			errors = append(errors, err.Error())
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("signature verification failed: %s", strings.Join(errors, "; "))
	}

	return nil
}

// convertTokenProtoSignaturesToOperatorSpecific converts token proto signatures to OperatorSpecificOwnerSignature format
func convertTokenProtoSignaturesToOperatorSpecific(
	ttxoSignatures []*tokenpb.SignatureWithIndex,
	finalTokenTransactionHash []byte,
	operatorIdentityPublicKey []byte,
) []*sparkpb.OperatorSpecificOwnerSignature {
	operatorSpecificSignatures := make([]*sparkpb.OperatorSpecificOwnerSignature, 0, len(ttxoSignatures))
	for _, operatorSignatures := range ttxoSignatures {
		operatorSpecificSignatures = append(operatorSpecificSignatures, &sparkpb.OperatorSpecificOwnerSignature{
			OwnerSignature: protoconverter.SparkSignatureWithIndexFromTokenProto(operatorSignatures),
			Payload: &sparkpb.OperatorSpecificTokenTransactionSignablePayload{
				FinalTokenTransactionHash: finalTokenTransactionHash,
				OperatorIdentityPublicKey: operatorIdentityPublicKey,
			},
		})
	}
	return operatorSpecificSignatures
}
