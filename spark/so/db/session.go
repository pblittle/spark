package db

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lightsparkdev/spark/common/logging"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/errors"
)

var (
	ErrTxBeginTimeout   = errors.UnavailableErrorf("The service is currently unavailable. Please try again later.")
	DefaultNewTxTimeout = 15 * time.Second
)

// SessionFactory is an interface for creating a new Session.
type SessionFactory interface {
	NewSession() *Session
}

// DefaultSessionFactory is the default implementation of SessionFactory that creates sessions
// using an ent.Client. It also provides a timeout for how long it will wait for a new transaction
// to be started, to prevent requests from hanging indefinitely if the database is unresponsive or
// overloaded.
type DefaultSessionFactory struct {
	dbClient     *ent.Client
	newTxTimeout *time.Duration
}

func NewDefaultSessionFactory(dbClient *ent.Client, newTxTimeout *time.Duration) *DefaultSessionFactory {
	return &DefaultSessionFactory{
		dbClient:     dbClient,
		newTxTimeout: newTxTimeout,
	}
}

func (f *DefaultSessionFactory) NewSession() *Session {
	provider := NewTxProviderWithTimeout(ent.NewEntClientTxProvider(f.dbClient), f.newTxTimeout)

	return &Session{
		provider:  provider,
		currentTx: nil,
		mu:        sync.Mutex{},
	}
}

// A Session manages a transaction over the lifetime of a request or worker. It
// wraps a TxProvider for creating an initial transaction, and stores that transaction for
// subsequent requests until the transaction is committed or rolled back. Once the transaction
// is finished, it is cleared so a new one can begin the next time `GetOrBeginTx` is called.
type Session struct {
	// TxProvider is used to create a new transaction when needed.
	provider ent.TxProvider
	// Mutex for ensuring thread-safe access to `currentTx` and `timer`.
	mu sync.Mutex
	// The current transaction being tracked by this session if a transaction has been started. When
	// the tracked transaction is committed or rolled back successfully, this field is set back to nil.
	currentTx *ent.Tx
	// A timer for tracking how long a transaction is held. If a transaction is held for more than
	// a set amount of time, we log a warning. This is useful for tracking down long running
	// transactions.
	timer *time.Timer
}

// NewSession creates a new Session with a new transactions provided
// by an ent.ClientTxProvider wrapping the provided `ent.Client`.
func NewSession(dbClient *ent.Client, newTxTimeout *time.Duration) *Session {
	provider := NewTxProviderWithTimeout(ent.NewEntClientTxProvider(dbClient), newTxTimeout)

	return &Session{
		provider:  provider,
		currentTx: nil,
		mu:        sync.Mutex{},
	}
}

// GetOrBeginTx retrieves the current transaction if it exists, otherwise it begins a new one.
// Furthermore, it inserts commit and rollback hooks that will clear the current transaction
// should the transaction be finished by the caller.
func (s *Session) GetOrBeginTx(ctx context.Context) (*ent.Tx, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.currentTx == nil {
		logger := logging.GetLoggerFromContext(ctx)
		logger.Info("Creating new transaction")
		tx, err := s.provider.GetOrBeginTx(ctx)
		if err != nil {
			logger.Error("Failed to create new transaction", "error", err)
			return nil, err
		}
		logger.Info("New transaction created")
		s.currentTx = tx
		s.timer = time.AfterFunc(30*time.Second, func() {
			logger.Info("Transaction is held for more than 30 seconds")
		})

		tx.OnCommit(func(fn ent.Committer) ent.Committer {
			return ent.CommitFunc(func(ctx context.Context, tx *ent.Tx) error {
				s.mu.Lock()
				defer s.mu.Unlock()
				logger.Info("Transaction committed")
				err := fn.Commit(ctx, tx)
				if err != nil {
					logger.Error("Failed to commit transaction", "error", err)
				} else {
					// Only set the current tx to nil if the transaction was committed successfully.
					// Otherwise, the transaction will be rolled back at last.
					s.timer.Stop()
					s.timer = nil
					s.currentTx = nil
				}
				return err
			})
		})
		tx.OnRollback(func(fn ent.Rollbacker) ent.Rollbacker {
			return ent.RollbackFunc(func(ctx context.Context, tx *ent.Tx) error {
				s.mu.Lock()
				defer s.mu.Unlock()
				logger.Info("Transaction rolled back")
				err := fn.Rollback(ctx, tx)
				if err != nil {
					logger.Error("Failed to rollback transaction", "error", err)
				}
				s.timer.Stop()
				s.timer = nil
				s.currentTx = nil
				return err
			})
		})
	}
	return s.currentTx, nil
}

// GetTxIfExists retrieves the current transaction if it exists, without starting a new one. If
// no current transaction exists, then returns nil.
func (s *Session) GetTxIfExists() *ent.Tx {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentTx
}

// A wrapper around a TxProvider that includes a timeout for if it takes to long to call `GetOrBeginTx`.
type TxProviderWithTimeout struct {
	wrapped ent.TxProvider
	timeout time.Duration
}

func NewTxProviderWithTimeout(provider ent.TxProvider, timeout *time.Duration) *TxProviderWithTimeout {
	if timeout == nil {
		timeout = &DefaultNewTxTimeout
	}

	return &TxProviderWithTimeout{
		wrapped: provider,
		timeout: *timeout,
	}
}

func (t *TxProviderWithTimeout) GetOrBeginTx(ctx context.Context) (*ent.Tx, error) {
	if t.timeout <= 0 {
		// If the timeout is zero or negative, assume there is no timeout and we should call
		// `GetOrBeginTx` normally.
		return t.wrapped.GetOrBeginTx(ctx)
	}

	txChan := make(chan *ent.Tx)
	errChan := make(chan error)

	logger := logging.GetLoggerFromContext(ctx)

	timeoutCtx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()

	// We can't pass timeoutCtx directly into `NewTx`, because the context we pass into `NewTx` isn't
	// just for starting the transaction. It's also used for the lifetime of the transaction. So throw
	// this into a goroutine so that we can run a select on:
	//
	// 		1. A connection being acquired and a transaction being started successfully.
	//		2. An error occuring while staring the transaction.
	//		3. Neither (1) nor (2) happening within the timeout period.
	//
	// If (3) happens, this function will return an error AND the caller needs to cancel the context in
	// order to stop the transaction process.
	go func() {
		defer close(txChan)
		defer close(errChan)

		tx, err := t.wrapped.GetOrBeginTx(ctx)
		if err != nil {
			select {
			case errChan <- err:
			case <-timeoutCtx.Done():
				logger.Warn("Failed to start transaction within timeout", "error", err)
				return
			}
			return
		}

		select {
		case txChan <- tx:
		case <-timeoutCtx.Done():
			// If the timeout context is done, there are no receivers for the transaction, so we need to
			// rollback the transaction so that we aren't just leaving it idle.
			err := tx.Rollback()
			if err != nil {
				logger.Warn("Failed to rollback transaction after timeout", "error", err)
			}
			return
		}
	}()

	select {
	case tx := <-txChan:
		return tx, nil
	case err := <-errChan:
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	case <-timeoutCtx.Done():
		return nil, ErrTxBeginTimeout
	}
}
