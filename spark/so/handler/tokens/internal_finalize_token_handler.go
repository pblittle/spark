package tokens

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/lightsparkdev/spark/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/helper"
	"github.com/lightsparkdev/spark/so/protoconverter"
	"github.com/lightsparkdev/spark/so/tokens"
	"github.com/lightsparkdev/spark/so/utils"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type InternalFinalizeTokenHandler struct {
	config *so.Config
}

// NewInternalFinalizeTokenHandler creates a new InternalFinalizeTokenHandler.
func NewInternalFinalizeTokenHandler(config *so.Config) *InternalFinalizeTokenHandler {
	return &InternalFinalizeTokenHandler{
		config: config,
	}
}

func (h *InternalFinalizeTokenHandler) FinalizeTokenTransactionInternal(
	ctx context.Context,
	req *pb.FinalizeTokenTransactionRequest,
) (*emptypb.Empty, error) {
	tokenProtoTokenTransaction, err := protoconverter.TokenProtoFromSparkTokenTransaction(req.FinalTokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to convert token transaction to spark token transaction: %w", err)
	}
	tokenTransaction, err := ent.FetchAndLockTokenTransactionData(ctx, tokenProtoTokenTransaction)
	if err != nil {
		return nil, tokens.FormatErrorWithTransactionEnt(tokens.ErrFailedToFetchTransaction, tokenTransaction, err)
	}

	// Verify that the transaction is in a signed state before finalizing
	if tokenTransaction.Status != st.TokenTransactionStatusSigned {
		return nil, tokens.FormatErrorWithTransactionEnt(
			fmt.Sprintf(tokens.ErrInvalidTransactionStatus,
				tokenTransaction.Status, st.TokenTransactionStatusSigned),
			tokenTransaction, nil)
	}

	// Verify status of created outputs and spent outputs
	invalidOutputs := validateOutputs(tokenTransaction.Edges.CreatedOutput, st.TokenOutputStatusCreatedSigned)
	if len(tokenTransaction.Edges.SpentOutput) > 0 {
		invalidOutputs = append(invalidOutputs, validateInputs(tokenTransaction.Edges.SpentOutput, st.TokenOutputStatusSpentSigned)...)
	}

	if len(invalidOutputs) > 0 {
		return nil, tokens.FormatErrorWithTransactionEnt(fmt.Sprintf("%s: %s", tokens.ErrInvalidOutputs, strings.Join(invalidOutputs, "; ")), tokenTransaction, nil)
	}

	if len(tokenTransaction.Edges.SpentOutput) != len(req.RevocationSecrets) {
		return nil, tokens.FormatErrorWithTransactionEnt(
			fmt.Sprintf("number of revocation keys (%d) does not match number of spent outputs (%d)",
				len(req.RevocationSecrets),
				len(tokenTransaction.Edges.SpentOutput)),
			tokenTransaction, nil)
	}
	revocationSecretMap := make(map[int][]byte)
	for _, revocationSecret := range req.RevocationSecrets {
		revocationSecretMap[int(revocationSecret.InputIndex)] = revocationSecret.RevocationSecret
	}
	// Validate that we have exactly one revocation secret for each input index
	// and that they form a contiguous sequence from 0 to len(tokenTransaction.Edges.SpentOutput)-1
	for i := 0; i < len(tokenTransaction.Edges.SpentOutput); i++ {
		if _, exists := revocationSecretMap[i]; !exists {
			return nil, tokens.FormatErrorWithTransactionEnt(
				fmt.Sprintf("missing revocation secret for input index %d", i),
				tokenTransaction, nil)
		}
	}

	revocationSecrets := make([]*secp256k1.PrivateKey, len(revocationSecretMap))
	revocationCommitments := make([][]byte, len(revocationSecretMap))

	spentOutputs := slices.SortedFunc(slices.Values(tokenTransaction.Edges.SpentOutput), func(a, b *ent.TokenOutput) int {
		return cmp.Compare(a.SpentTransactionInputVout, b.SpentTransactionInputVout)
	})

	// Match each output with its corresponding revocation secret
	for i, output := range spentOutputs {
		index := int(output.SpentTransactionInputVout)
		revocationSecret, exists := revocationSecretMap[index]
		if !exists {
			return nil, tokens.FormatErrorWithTransactionEnt(
				fmt.Sprintf("missing revocation secret for input at index %d", index),
				tokenTransaction, nil)
		}

		revocationPrivateKey, err := common.PrivateKeyFromBytes(revocationSecret)
		if err != nil {
			return nil, tokens.FormatErrorWithTransactionEnt(tokens.ErrFailedToParseRevocationPrivateKey, tokenTransaction, err)
		}

		revocationSecrets[i] = revocationPrivateKey
		revocationCommitments[i] = output.WithdrawRevocationCommitment
	}

	err = utils.ValidateRevocationKeys(revocationSecrets, revocationCommitments)
	if err != nil {
		return nil, tokens.FormatErrorWithTransactionEnt(tokens.ErrFailedToValidateRevocationKeys, tokenTransaction, err)
	}

	err = ent.UpdateFinalizedTransaction(ctx, tokenTransaction, req.RevocationSecrets)
	if err != nil {
		return nil, tokens.FormatErrorWithTransactionEnt(fmt.Sprintf(tokens.ErrFailedToUpdateOutputs, "finalizing"), tokenTransaction, err)
	}

	return &emptypb.Empty{}, nil
}

func (h *InternalFinalizeTokenHandler) CancelOrFinalizeExpiredTokenTransaction(
	ctx context.Context,
	config *so.Config,
	lockedTokenTransaction *ent.TokenTransaction,
) error {
	// Verify that the transaction is in a cancellable state locally
	if lockedTokenTransaction.Status != st.TokenTransactionStatusSigned &&
		lockedTokenTransaction.Status != st.TokenTransactionStatusStarted {
		return tokens.FormatErrorWithTransactionEnt(
			fmt.Sprintf(tokens.ErrInvalidTransactionStatus,
				lockedTokenTransaction.Status, fmt.Sprintf("%s or %s", st.TokenTransactionStatusStarted, st.TokenTransactionStatusSigned)),
			lockedTokenTransaction, nil)
	}

	// Verify with the other SOs that the transaction is in a cancellable state.
	// Each SO verifies that:
	// 1. No SO has moved the transaction to a 'Finalized' state.
	// 2. (# of SOs) - threshold have not progressed the transaction to a 'Signed' state.
	allSelection := helper.OperatorSelection{Option: helper.OperatorSelectionOptionAll}
	responses, err := helper.ExecuteTaskWithAllOperators(ctx, config, &allSelection, func(ctx context.Context, operator *so.SigningOperator) (any, error) {
		var internalResp *pb.QueryTokenTransactionsResponse
		var err error

		if operator.Identifier == h.config.Identifier {
			queryTokenHandler := NewQueryTokenHandler(config)
			internalResp, err = queryTokenHandler.QueryTokenTransactions(ctx, &pb.QueryTokenTransactionsRequest{
				TokenTransactionHashes: [][]byte{lockedTokenTransaction.FinalizedTokenTransactionHash},
			})
			if err != nil {
				return nil, tokens.FormatErrorWithTransactionEnt(
					fmt.Sprintf(tokens.ErrFailedToQueryOperatorForCancel, operator.Identifier),
					lockedTokenTransaction, err)
			}
		} else {
			conn, err := operator.NewGRPCConnection()
			if err != nil {
				return nil, tokens.FormatErrorWithTransactionEnt(
					fmt.Sprintf(tokens.ErrFailedToConnectToOperatorForCancel, operator.Identifier),
					lockedTokenTransaction, err)
			}
			defer conn.Close()

			client := pb.NewSparkServiceClient(conn)
			internalResp, err = client.QueryTokenTransactions(ctx, &pb.QueryTokenTransactionsRequest{
				TokenTransactionHashes: [][]byte{lockedTokenTransaction.FinalizedTokenTransactionHash},
			})
			if err != nil {
				return nil, tokens.FormatErrorWithTransactionEnt(
					fmt.Sprintf(tokens.ErrFailedToQueryOperatorForCancel, operator.Identifier),
					lockedTokenTransaction, err)
			}
		}

		return internalResp, err
	})
	if err != nil {
		return tokens.FormatErrorWithTransactionEnt(tokens.ErrFailedToExecuteWithAllOperators, lockedTokenTransaction, err)
	}

	// Check if any operator has finalized the transaction
	signedCount := 0
	for _, resp := range responses {
		queryResp, ok := resp.(*pb.QueryTokenTransactionsResponse)
		if !ok || queryResp == nil {
			return tokens.FormatErrorWithTransactionEnt("invalid response from operator", lockedTokenTransaction, nil)
		}

		for _, txWithStatus := range queryResp.TokenTransactionsWithStatus {
			// If the transaction has been finalized by a different operator, it indicates that threshold operators have signed.
			// This could occur if a wallet attempted to finalized but did not successfully complete the request with all SOs.
			// In this case, finalize the transaction with the revocation secrets provided by the operator that finalized the transaction.
			if txWithStatus.Status == pb.TokenTransactionStatus_TOKEN_TRANSACTION_FINALIZED {
				revocationSecrets := make([]*pb.RevocationSecretWithIndex, len(lockedTokenTransaction.Edges.SpentOutput))
				revocationSecretMap := make(map[string]*pb.SpentTokenOutputMetadata)
				if txWithStatus.ConfirmationMetadata == nil {
					return tokens.FormatErrorWithTransactionEnt("missing confirmation metadata", lockedTokenTransaction, nil)
				}
				if len(txWithStatus.ConfirmationMetadata.SpentTokenOutputsMetadata) != len(lockedTokenTransaction.Edges.SpentOutput) {
					return tokens.FormatErrorWithTransactionEnt("confirmation metadata does not match number of spent outputs", lockedTokenTransaction, nil)
				}

				for _, metadata := range txWithStatus.ConfirmationMetadata.SpentTokenOutputsMetadata {
					revocationSecretMap[metadata.OutputId] = metadata
				}

				tokenTransactionProto, err := lockedTokenTransaction.MarshalProto(config)
				if err != nil {
					return tokens.FormatErrorWithTransactionEnt("failed to marshal token transaction", lockedTokenTransaction, err)
				}

				tokenTransactionProtoV0, err := protoconverter.SparkTokenTransactionFromTokenProto(tokenTransactionProto)
				if err != nil {
					return tokens.FormatErrorWithTransactionEnt("failed to marshal token transaction into v0", lockedTokenTransaction, err)
				}

				// Match received revocation secrets to their input index saved in the TokenOutput entity using output_id.
				for i, output := range lockedTokenTransaction.Edges.SpentOutput {
					metadata, exists := revocationSecretMap[output.ID.String()]
					if !exists {
						return tokens.FormatErrorWithTransactionEnt(
							fmt.Sprintf("missing revocation secret for output %s", output.ID.String()),
							lockedTokenTransaction, nil)
					}
					revocationSecrets[i] = &pb.RevocationSecretWithIndex{
						InputIndex:       uint32(output.SpentTransactionInputVout),
						RevocationSecret: metadata.RevocationSecret,
					}
				}
				finalizeReq := &pb.FinalizeTokenTransactionRequest{
					FinalTokenTransaction: tokenTransactionProtoV0,
					RevocationSecrets:     revocationSecrets,
					IdentityPublicKey:     nil,
				}

				_, err = h.FinalizeTokenTransactionInternal(ctx, finalizeReq)
				if err != nil {
					return tokens.FormatErrorWithTransactionEnt("failed to finalize transaction", lockedTokenTransaction, err)
				}

				return tokens.FormatErrorWithTransactionEnt("transaction has already been finalized by at least one operator, cannot cancel", lockedTokenTransaction, nil)
			}
			if txWithStatus.Status == pb.TokenTransactionStatus_TOKEN_TRANSACTION_SIGNED ||
				// Check for this just in case. Its unlikely, but it is theoretically possible for a race condition where
				// the transaction is signed by the final operator needed for threshold just as the transaction is cancelled by a
				// different operator. In this event, the operators that didn't cancel yet should not cancel to avoid a fully
				// signed transaction being cancelled in all SOs.
				// if a revocation secret is provided (which proves that all SOs have signed)
				txWithStatus.Status == pb.TokenTransactionStatus_TOKEN_TRANSACTION_SIGNED_CANCELLED {
				signedCount++
			}
		}
	}

	// Check if too many operators have already signed
	operatorCount := len(config.GetSigningOperatorList())
	if signedCount == operatorCount {
		return tokens.FormatErrorWithTransactionEnt(
			fmt.Sprintf("transaction has been signed by %d operators, which exceeds the cancellation threshold of %d",
				signedCount, operatorCount),
			lockedTokenTransaction, nil)
	}

	err = ent.UpdateCancelledTransaction(ctx, lockedTokenTransaction)
	if err != nil {
		return tokens.FormatErrorWithTransactionEnt(fmt.Sprintf(tokens.ErrFailedToUpdateOutputs, "canceling"), lockedTokenTransaction, err)
	}

	return nil
}

func (h *InternalFinalizeTokenHandler) FinalizeCoordinatedTokenTransactionInternal(
	ctx context.Context,
	tokenTransactionHash []byte,
	revocationSecretsToFinalize []*ent.RecoveredRevocationSecret,
) error {
	tokenTransaction, err := ent.FetchAndLockTokenTransactionDataByHash(ctx, tokenTransactionHash)
	if err != nil {
		return tokens.FormatErrorWithTransactionEnt(tokens.ErrFailedToFetchTransaction, tokenTransaction, err)
	}

	if tokenTransaction.Status != st.TokenTransactionStatusSigned && tokenTransaction.Status != st.TokenTransactionStatusRevealed {
		return tokens.FormatErrorWithTransactionEnt(
			fmt.Sprintf(tokens.ErrInvalidTransactionStatus,
				tokenTransaction.Status, fmt.Sprintf("%s or %s", st.TokenTransactionStatusSigned, st.TokenTransactionStatusRevealed)),
			tokenTransaction, nil)
	}
	invalidOutputs := validateOutputs(tokenTransaction.Edges.CreatedOutput, st.TokenOutputStatusCreatedSigned)
	if len(tokenTransaction.Edges.SpentOutput) > 0 {
		invalidOutputs = append(invalidOutputs, validateInputs(tokenTransaction.Edges.SpentOutput, st.TokenOutputStatusSpentSigned)...)
	}
	if len(invalidOutputs) > 0 {
		return tokens.FormatErrorWithTransactionEnt(fmt.Sprintf("%s: %s", tokens.ErrInvalidOutputs, strings.Join(invalidOutputs, "; ")), tokenTransaction, nil)
	}
	if len(tokenTransaction.Edges.SpentOutput) != len(revocationSecretsToFinalize) {
		return tokens.FormatErrorWithTransactionEnt(
			fmt.Sprintf("number of revocation keys (%d) does not match number of spent outputs (%d)",
				len(revocationSecretsToFinalize),
				len(tokenTransaction.Edges.SpentOutput)),
			tokenTransaction, nil)
	}

	err = ent.FinalizeCoordinatedTokenTransactionWithRevocationKeys(ctx, tokenTransaction, revocationSecretsToFinalize)
	if err != nil {
		return tokens.FormatErrorWithTransactionEnt(fmt.Sprintf(tokens.ErrFailedToUpdateOutputs, "finalizing"), tokenTransaction, err)
	}
	return nil
}
