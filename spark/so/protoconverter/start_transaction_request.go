package protoconverter

import (
	"fmt"
	"time"

	sparkpb "github.com/lightsparkdev/spark/proto/spark"
	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"
)

// SparkStartTokenTransactionRequestFromTokenProto converts a StartTransactionRequest to a StartTokenTransactionRequest.
func SparkStartTokenTransactionRequestFromTokenProto(startReq *tokenpb.StartTransactionRequest) (*sparkpb.StartTokenTransactionRequest, error) {
	if startReq == nil {
		return nil, fmt.Errorf("input start transaction request cannot be nil")
	}

	sparkTokenTransaction, err := SparkTokenTransactionFromTokenProto(startReq.PartialTokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to convert token transaction: %w", err)
	}

	var tokenTransactionSignatures *sparkpb.TokenTransactionSignatures
	if len(startReq.PartialTokenTransactionOwnerSignatures) > 0 {
		// Extract owner signatures from the SignatureWithIndex slice
		ownerSignatures := make([]*sparkpb.SignatureWithIndex, len(startReq.PartialTokenTransactionOwnerSignatures))
		for i, sig := range startReq.PartialTokenTransactionOwnerSignatures {
			ownerSignatures[i] = SparkSignatureWithIndexFromTokenProto(sig)
		}

		tokenTransactionSignatures = &sparkpb.TokenTransactionSignatures{
			OwnerSignatures: ownerSignatures,
		}
	}

	sparkStartReq := &sparkpb.StartTokenTransactionRequest{
		IdentityPublicKey:          startReq.IdentityPublicKey,
		PartialTokenTransaction:    sparkTokenTransaction,
		TokenTransactionSignatures: tokenTransactionSignatures,
		// Note: SparkPaymentIntent is not available in StartTransactionRequest
		// so it will be empty when converting from StartTransactionRequest
		// Note: ValidityDurationSeconds is not available in StartTokenTransactionRequest
		// so it will be lost when converting from StartTransactionRequest
	}

	return sparkStartReq, nil
}

// TokenProtoStartTransactionRequestFromSpark converts a StartTokenTransactionRequest to a StartTransactionRequest.
func TokenProtoStartTransactionRequestFromSpark(sparkStartReq *sparkpb.StartTokenTransactionRequest, validityDuration time.Duration) (*tokenpb.StartTransactionRequest, error) {
	if sparkStartReq == nil {
		return nil, fmt.Errorf("input start token transaction request cannot be nil")
	}

	tokenTransaction, err := TokenProtoFromSparkTokenTransaction(sparkStartReq.PartialTokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to convert token transaction: %w", err)
	}

	var partialTokenTransactionOwnerSignatures []*tokenpb.SignatureWithIndex
	if sparkStartReq.TokenTransactionSignatures != nil && len(sparkStartReq.TokenTransactionSignatures.OwnerSignatures) > 0 {
		partialTokenTransactionOwnerSignatures = make([]*tokenpb.SignatureWithIndex, len(sparkStartReq.TokenTransactionSignatures.OwnerSignatures))
		for i, sig := range sparkStartReq.TokenTransactionSignatures.OwnerSignatures {
			partialTokenTransactionOwnerSignatures[i] = &tokenpb.SignatureWithIndex{
				Signature:  sig.Signature,
				InputIndex: sig.InputIndex,
			}
		}
	}

	startReq := &tokenpb.StartTransactionRequest{
		IdentityPublicKey:                      sparkStartReq.IdentityPublicKey,
		PartialTokenTransaction:                tokenTransaction,
		PartialTokenTransactionOwnerSignatures: partialTokenTransactionOwnerSignatures,
		ValidityDurationSeconds:                uint64(validityDuration.Seconds()),
		// Note: SparkPaymentIntent is not available in StartTransactionRequest
		// so it will be lost when converting from StartTokenTransactionRequest
	}

	return startReq, nil
}
