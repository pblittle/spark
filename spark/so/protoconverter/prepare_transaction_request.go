package protoconverter

import (
	"fmt"

	pb "github.com/lightsparkdev/spark/proto/spark"
	internalpb "github.com/lightsparkdev/spark/proto/spark_internal"
	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"
	tokeninternalpb "github.com/lightsparkdev/spark/proto/spark_token_internal"
)

// SparkStartTokenTransactionInternalRequestFromTokenProto converts a PrepareTransactionRequest to a StartTokenTransactionInternalRequest.
func SparkStartTokenTransactionInternalRequestFromTokenProto(prepareReq *tokeninternalpb.PrepareTransactionRequest) (*internalpb.StartTokenTransactionInternalRequest, error) {
	if prepareReq == nil {
		return nil, fmt.Errorf("input prepare transaction request cannot be nil")
	}

	sparkTokenTransaction, err := SparkTokenTransactionFromTokenProto(prepareReq.FinalTokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to convert token transaction: %w", err)
	}

	var tokenTransactionSignatures *pb.TokenTransactionSignatures
	if len(prepareReq.TokenTransactionSignatures) > 0 {
		ownerSignatures := make([]*pb.SignatureWithIndex, len(prepareReq.TokenTransactionSignatures))
		for i, sig := range prepareReq.TokenTransactionSignatures {
			ownerSignatures[i] = &pb.SignatureWithIndex{
				Signature:  sig.Signature,
				InputIndex: sig.InputIndex,
			}
		}

		tokenTransactionSignatures = &pb.TokenTransactionSignatures{
			OwnerSignatures: ownerSignatures,
		}
	}

	startReq := &internalpb.StartTokenTransactionInternalRequest{
		FinalTokenTransaction:      sparkTokenTransaction,
		TokenTransactionSignatures: tokenTransactionSignatures,
		KeyshareIds:                prepareReq.KeyshareIds,
		CoordinatorPublicKey:       prepareReq.CoordinatorPublicKey,
	}

	return startReq, nil
}

// TokenProtoPrepareTransactionRequestFromSpark converts a StartTokenTransactionInternalRequest to a PrepareTransactionRequest.
func TokenProtoPrepareTransactionRequestFromSpark(startReq *internalpb.StartTokenTransactionInternalRequest) (*tokeninternalpb.PrepareTransactionRequest, error) {
	if startReq == nil {
		return nil, fmt.Errorf("input start token transaction internal request cannot be nil")
	}

	tokenTransaction, err := TokenProtoFromSparkTokenTransaction(startReq.FinalTokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to convert token transaction: %w", err)
	}

	var tokenTransactionSignatures []*tokenpb.SignatureWithIndex
	if startReq.TokenTransactionSignatures != nil && len(startReq.TokenTransactionSignatures.OwnerSignatures) > 0 {
		tokenTransactionSignatures = make([]*tokenpb.SignatureWithIndex, len(startReq.TokenTransactionSignatures.OwnerSignatures))
		for i, sig := range startReq.TokenTransactionSignatures.OwnerSignatures {
			tokenTransactionSignatures[i] = &tokenpb.SignatureWithIndex{
				Signature:  sig.Signature,
				InputIndex: sig.InputIndex,
			}
		}
	}

	prepareReq := &tokeninternalpb.PrepareTransactionRequest{
		FinalTokenTransaction:      tokenTransaction,
		TokenTransactionSignatures: tokenTransactionSignatures,
		KeyshareIds:                startReq.KeyshareIds,
		CoordinatorPublicKey:       startReq.CoordinatorPublicKey,
	}

	return prepareReq, nil
}
