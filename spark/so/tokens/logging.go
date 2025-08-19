package tokens

import (
	"encoding/hex"

	"github.com/lightsparkdev/spark/common/logging"
	"github.com/lightsparkdev/spark/so/ent"
)

func GetEntTokenTransactionAttrs(tokenTransaction *ent.TokenTransaction) []logging.Attr {
	return []logging.Attr{
		{Key: "transaction_uuid", Value: tokenTransaction.ID.String()},
		{Key: "transaction_hash", Value: hex.EncodeToString(tokenTransaction.FinalizedTokenTransactionHash)},
	}
}

func GetFinalizedTokenTransactionAttrs(finalizedTokenTransactionHash []byte) []logging.Attr {
	return []logging.Attr{
		{Key: "transaction_hash", Value: hex.EncodeToString(finalizedTokenTransactionHash)},
	}
}

func GetPartialTokenTransactionAttrs(partialTokenTransactionHash []byte) []logging.Attr {
	return []logging.Attr{
		{Key: "partial_transaction_hash", Value: hex.EncodeToString(partialTokenTransactionHash)},
	}
}
