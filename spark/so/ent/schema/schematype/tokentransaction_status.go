package schematype

type TokenTransactionStatus string

const (
	TokenTransactionStatusStarted TokenTransactionStatus = "STARTED"
	// TokenTransactionStatusStartedCancelled is the status if a transaction was started but then cancelled due to a threshold of the
	// signatures not being acquired.
	TokenTransactionStatusStartedCancelled TokenTransactionStatus = "STARTED_CANCELLED"
	// TokenTransactionStatusSigned is the status after a transaction has been signed by this operator.
	TokenTransactionStatusSigned TokenTransactionStatus = "SIGNED"
	// TokenTransactionStatusRevealed is the status operators mark a transaction as once its spent output revocation
	// secrets have been revealed to another operator.
	TokenTransactionStatusRevealed TokenTransactionStatus = "REVEALED"
	// TokenTransactionStatusSignedCancelled is the status if a transaction was signed but then cancelled due to a threshold of the
	// signatures not being acquired.
	TokenTransactionStatusSignedCancelled TokenTransactionStatus = "SIGNED_CANCELLED"
	// TokenTransactionStatusFinalized is the status after the revocation keys for outputs have been shared with the operator.
	TokenTransactionStatusFinalized TokenTransactionStatus = "FINALIZED"
)

func (TokenTransactionStatus) Values() []string {
	return []string{
		string(TokenTransactionStatusStarted),
		string(TokenTransactionStatusStartedCancelled),
		string(TokenTransactionStatusSigned),
		string(TokenTransactionStatusRevealed),
		string(TokenTransactionStatusSignedCancelled),
		string(TokenTransactionStatusFinalized),
	}
}
