package protoconverter

import (
	"fmt"

	sparkpb "github.com/lightsparkdev/spark/proto/spark"
	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
)

// TokenProtoQueryTokenTransactionsRequestFromSpark converts sparkpb.QueryTokenTransactionsRequest to tokenpb.QueryTokenTransactionsRequest
func TokenProtoQueryTokenTransactionsRequestFromSpark(req *sparkpb.QueryTokenTransactionsRequest) *tokenpb.QueryTokenTransactionsRequest {
	return &tokenpb.QueryTokenTransactionsRequest{
		OutputIds:              req.OutputIds,
		OwnerPublicKeys:        req.OwnerPublicKeys,
		IssuerPublicKeys:       req.TokenPublicKeys, // Field name change: TokenPublicKeys -> IssuerPublicKeys
		TokenIdentifiers:       req.TokenIdentifiers,
		TokenTransactionHashes: req.TokenTransactionHashes,
		Limit:                  req.Limit,
		Offset:                 req.Offset,
	}
}

// SparkQueryTokenTransactionsResponseFromTokenProto converts tokenpb.QueryTokenTransactionsResponse to sparkpb.QueryTokenTransactionsResponse
func SparkQueryTokenTransactionsResponseFromTokenProto(resp *tokenpb.QueryTokenTransactionsResponse) (*sparkpb.QueryTokenTransactionsResponse, error) {
	sparkTransactions := make([]*sparkpb.TokenTransactionWithStatus, 0, len(resp.TokenTransactionsWithStatus))

	for _, tokenTxWithStatus := range resp.TokenTransactionsWithStatus {
		// Convert token transaction to spark transaction
		sparkTransaction, err := SparkTokenTransactionFromTokenProto(tokenTxWithStatus.TokenTransaction)
		if err != nil {
			return nil, fmt.Errorf("failed to convert token transaction to spark transaction: %w", err)
		}

		sparkTxWithStatus := &sparkpb.TokenTransactionWithStatus{
			TokenTransaction:     sparkTransaction,
			Status:               ConvertTokenTransactionStatusToSparkPb(tokenTxWithStatus.Status),
			TokenTransactionHash: tokenTxWithStatus.TokenTransactionHash,
		}

		if tokenTxWithStatus.ConfirmationMetadata != nil {
			sparkSpentOutputsMetadata := make([]*sparkpb.SpentTokenOutputMetadata, 0, len(tokenTxWithStatus.ConfirmationMetadata.SpentTokenOutputsMetadata))

			for _, spentOutput := range tokenTxWithStatus.ConfirmationMetadata.SpentTokenOutputsMetadata {
				sparkSpentOutputsMetadata = append(sparkSpentOutputsMetadata, &sparkpb.SpentTokenOutputMetadata{
					OutputId:         spentOutput.OutputId,
					RevocationSecret: spentOutput.RevocationSecret,
				})
			}

			sparkTxWithStatus.ConfirmationMetadata = &sparkpb.TokenTransactionConfirmationMetadata{
				SpentTokenOutputsMetadata: sparkSpentOutputsMetadata,
			}
		}

		sparkTransactions = append(sparkTransactions, sparkTxWithStatus)
	}

	return &sparkpb.QueryTokenTransactionsResponse{
		TokenTransactionsWithStatus: sparkTransactions,
		Offset:                      resp.Offset,
	}, nil
}

// ConvertTokenTransactionStatusToTokenPb converts from st.TokenTransactionStatus to tokenpb.TokenTransactionStatus
func ConvertTokenTransactionStatusToTokenPb(status st.TokenTransactionStatus) tokenpb.TokenTransactionStatus {
	switch status {
	case st.TokenTransactionStatusStarted:
		return tokenpb.TokenTransactionStatus_TOKEN_TRANSACTION_STARTED
	case st.TokenTransactionStatusStartedCancelled:
		return tokenpb.TokenTransactionStatus_TOKEN_TRANSACTION_STARTED_CANCELLED
	case st.TokenTransactionStatusSigned:
		return tokenpb.TokenTransactionStatus_TOKEN_TRANSACTION_SIGNED
	case st.TokenTransactionStatusSignedCancelled:
		return tokenpb.TokenTransactionStatus_TOKEN_TRANSACTION_SIGNED_CANCELLED
	case st.TokenTransactionStatusRevealed:
		return tokenpb.TokenTransactionStatus_TOKEN_TRANSACTION_REVEALED
	case st.TokenTransactionStatusFinalized:
		return tokenpb.TokenTransactionStatus_TOKEN_TRANSACTION_FINALIZED
	default:
		return tokenpb.TokenTransactionStatus_TOKEN_TRANSACTION_UNKNOWN
	}
}

// ConvertTokenTransactionStatusToSparkPb converts from tokenpb.TokenTransactionStatus to sparkpb.TokenTransactionStatus
func ConvertTokenTransactionStatusToSparkPb(status tokenpb.TokenTransactionStatus) sparkpb.TokenTransactionStatus {
	switch status {
	case tokenpb.TokenTransactionStatus_TOKEN_TRANSACTION_STARTED:
		return sparkpb.TokenTransactionStatus_TOKEN_TRANSACTION_STARTED
	case tokenpb.TokenTransactionStatus_TOKEN_TRANSACTION_STARTED_CANCELLED:
		return sparkpb.TokenTransactionStatus_TOKEN_TRANSACTION_STARTED_CANCELLED
	case tokenpb.TokenTransactionStatus_TOKEN_TRANSACTION_SIGNED:
		return sparkpb.TokenTransactionStatus_TOKEN_TRANSACTION_SIGNED
	case tokenpb.TokenTransactionStatus_TOKEN_TRANSACTION_SIGNED_CANCELLED:
		return sparkpb.TokenTransactionStatus_TOKEN_TRANSACTION_SIGNED_CANCELLED
	case tokenpb.TokenTransactionStatus_TOKEN_TRANSACTION_REVEALED:
		return sparkpb.TokenTransactionStatus_TOKEN_TRANSACTION_REVEALED
	case tokenpb.TokenTransactionStatus_TOKEN_TRANSACTION_FINALIZED:
		return sparkpb.TokenTransactionStatus_TOKEN_TRANSACTION_FINALIZED
	default:
		return sparkpb.TokenTransactionStatus_TOKEN_TRANSACTION_UNKNOWN
	}
}
