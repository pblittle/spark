package protoconverter

import (
	"fmt"

	sparkpb "github.com/lightsparkdev/spark/proto/spark"
	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"
)

// SparkStartTokenTransactionResponseFromTokenProto converts a StartTransactionResponse to a StartTokenTransactionResponse.
func SparkStartTokenTransactionResponseFromTokenProto(startResp *tokenpb.StartTransactionResponse) (*sparkpb.StartTokenTransactionResponse, error) {
	if startResp == nil {
		return nil, fmt.Errorf("input start transaction response cannot be nil")
	}

	sparkTokenTransaction, err := SparkTokenTransactionFromTokenProto(startResp.FinalTokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to convert token transaction: %w", err)
	}

	sparkStartResp := &sparkpb.StartTokenTransactionResponse{
		FinalTokenTransaction: sparkTokenTransaction,
		KeyshareInfo:          startResp.KeyshareInfo,
	}

	return sparkStartResp, nil
}

// TokenProtoStartTransactionResponseFromSpark converts a StartTokenTransactionResponse to a StartTransactionResponse.
func TokenProtoStartTransactionResponseFromSpark(sparkStartResp *sparkpb.StartTokenTransactionResponse) (*tokenpb.StartTransactionResponse, error) {
	if sparkStartResp == nil {
		return nil, fmt.Errorf("input start token transaction response cannot be nil")
	}

	tokenTransaction, err := TokenProtoFromSparkTokenTransaction(sparkStartResp.FinalTokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to convert token transaction: %w", err)
	}

	startResp := &tokenpb.StartTransactionResponse{
		FinalTokenTransaction: tokenTransaction,
		KeyshareInfo:          sparkStartResp.KeyshareInfo,
	}

	return startResp, nil
}
