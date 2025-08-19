package ent

import (
	"context"
	"fmt"
)

// contextKey is a type for context keys.
type contextKey string

// txProviderKey is the context key for the transaction provider.
const txProviderKey contextKey = "txProvider"

// A TxProvider is an interface that provides a method to either get an existing transaction,
// or begin a new transaction if none exists.
type TxProvider interface {
	GetOrBeginTx(context.Context) (*Tx, error)
}

// ClientTxProvider is a TxProvider that uses an underlying ent.Client to create new transactions. This always
// returns a new transaction.
type ClientTxProvider struct {
	dbClient *Client
}

func NewEntClientTxProvider(dbClient *Client) *ClientTxProvider {
	return &ClientTxProvider{dbClient: dbClient}
}

func (e *ClientTxProvider) GetOrBeginTx(ctx context.Context) (*Tx, error) {
	tx, err := e.dbClient.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	return tx, nil
}

// Inject the transaction provider into the context. This should ONLY be called from the start of
// a request or worker context (e.g. in a top-level gRPC interceptor).
func Inject(ctx context.Context, txProvider TxProvider) context.Context {
	return context.WithValue(ctx, txProviderKey, txProvider)
}

// GetDbFromContext returns the database transaction from the context.
func GetDbFromContext(ctx context.Context) (*Tx, error) {
	if txProvider, ok := ctx.Value(txProviderKey).(TxProvider); ok {
		return txProvider.GetOrBeginTx(ctx)
	}

	return nil, fmt.Errorf("no transaction provider found in context")
}

// DbCommit gets the transaction from the context and commits it.
func DbCommit(ctx context.Context) error {
	tx, err := GetDbFromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get transaction from context: %w", err)
	}

	if tx == nil {
		return fmt.Errorf("no transaction found in context")
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DbRollback gets the transaction from the context and rolls it back.
func DbRollback(ctx context.Context) error {
	tx, err := GetDbFromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get transaction from context: %w", err)
	}

	if tx == nil {
		return fmt.Errorf("no transaction found in context")
	}

	if err := tx.Rollback(); err != nil {
		return fmt.Errorf("failed to rollback transaction: %w", err)
	}

	return nil
}
