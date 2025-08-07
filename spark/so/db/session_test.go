package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lightsparkdev/spark/so/ent"
	"github.com/stretchr/testify/require"
)

// A TxProvider that never returns a transaction.
type NeverTxProvider struct{}

func (p *NeverTxProvider) GetOrBeginTx(ctx context.Context) (*ent.Tx, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A TxProvider that simulates a slow transaction provider that waits for an external trigger before
// returning a transaction.
type SlowTxProvider struct {
	tx      *ent.Tx
	trigger <-chan struct{}
}

func (p *SlowTxProvider) GetOrBeginTx(ctx context.Context) (*ent.Tx, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.trigger:
		return p.tx, nil
	}
}

func TestSession_GetOrBeginTxReturnsSameTx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbClient := NewTestSQLiteClient(t)
	defer dbClient.Close()

	session := NewDefaultSessionFactory(dbClient, nil).NewSession()

	tx1, err := session.GetOrBeginTx(ctx)
	require.NoError(t, err, "Expected to retrieve a transaction")

	tx2, err := session.GetOrBeginTx(ctx)
	require.NoError(t, err, "Expected to retrieve the same transaction")

	require.Equal(t, tx1, tx2, "Expected both transactions to be the same")
}

func TestSession_GetCurrentTxReturnsNilWithNoTx(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbClient := NewTestSQLiteClient(t)
	defer dbClient.Close()

	session := NewDefaultSessionFactory(dbClient, nil).NewSession()

	tx := session.GetTxIfExists()
	require.Nil(t, tx, "Expected no current transaction to exist")
}

func TestSession_GetCurrentTxReturnsNilAfterSuccessfulCommit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbClient := NewTestSQLiteClient(t)
	defer dbClient.Close()

	session := NewDefaultSessionFactory(dbClient, nil).NewSession()

	tx, err := session.GetOrBeginTx(ctx)
	require.NoError(t, err, "Expected to retrieve a transaction")

	err = tx.Commit()
	require.NoError(t, err, "Expected to commit the transaction successfully")

	currentTx := session.GetTxIfExists()
	require.Nil(t, currentTx, "Expected no current transaction to exist after commit")
}

func TestSession_GetCurrentTxReturnsNilAfterSuccessfulRollback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbClient := NewTestSQLiteClient(t)
	defer dbClient.Close()

	session := NewDefaultSessionFactory(dbClient, nil).NewSession()

	tx, err := session.GetOrBeginTx(ctx)
	require.NoError(t, err, "Expected to retrieve a transaction")

	err = tx.Rollback()
	require.NoError(t, err, "Expected to rollback the transaction successfully")

	currentTx := session.GetTxIfExists()
	require.Nil(t, currentTx, "Expected no current transaction to exist after rollback")
}

func TestSession_GetCurrrentTxReturnsSameTxAfterFailedCommit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbClient := NewTestSQLiteClient(t)
	defer dbClient.Close()

	session := NewDefaultSessionFactory(dbClient, nil).NewSession()

	tx, err := session.GetOrBeginTx(ctx)
	require.NoError(t, err, "Expected to retrieve a transaction")

	tx.OnCommit(func(fn ent.Committer) ent.Committer {
		return ent.CommitFunc(func(ctx context.Context, tx *ent.Tx) error {
			return fmt.Errorf("commit failed because you asked it to")
		})
	})

	err = tx.Commit()
	require.Error(t, err, "Expected commit to fail")

	currentTx := session.GetTxIfExists()
	require.Equal(t, tx, currentTx, "Expected current transaction to be the same after failed commit")
}

func TestSession_GetCurrrentTxReturnsSameTxAfterFailedRollback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbClient := NewTestSQLiteClient(t)
	defer dbClient.Close()

	session := NewDefaultSessionFactory(dbClient, nil).NewSession()

	tx, err := session.GetOrBeginTx(ctx)
	require.NoError(t, err, "Expected to retrieve a transaction")

	tx.OnRollback(func(fn ent.Rollbacker) ent.Rollbacker {
		return ent.RollbackFunc(func(ctx context.Context, tx *ent.Tx) error {
			return fmt.Errorf("rollback failed because you asked it to")
		})
	})

	err = tx.Rollback()
	require.Error(t, err, "Expected rollback to fail")

	currentTx := session.GetTxIfExists()
	require.Nil(t, currentTx, "Expected current transaction to be nil after failed rollback")
}

func TestTxProviderWithTimeout_Success(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbClient := NewTestSQLiteClient(t)
	defer dbClient.Close()

	timeout := 5 * time.Second
	provider := NewTxProviderWithTimeout(ent.NewEntClientTxProvider(dbClient), &timeout)

	_, err := provider.GetOrBeginTx(ctx)
	require.NoError(t, err, "Expected to retrieve a transaction within the timeout")
}

func TestTxProviderWithTimeout_Timeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	timeout := 200 * time.Millisecond
	provider := NewTxProviderWithTimeout(&NeverTxProvider{}, &timeout)

	_, err := provider.GetOrBeginTx(ctx)
	require.ErrorIs(t, err, ErrTxBeginTimeout)
}

func TestTxProviderWithTimeout_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	timeout := 5 * time.Second
	provider := NewTxProviderWithTimeout(&NeverTxProvider{}, &timeout)

	_, err := provider.GetOrBeginTx(ctx)
	require.ErrorIs(t, err, ErrTxBeginTimeout)
}

func TestTxProviderWithTimeout_SlowProvider(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbClient := NewTestSQLiteClient(t)
	defer dbClient.Close()

	tx, err := dbClient.Tx(ctx)
	require.NoError(t, err, "Failed to create a transaction")

	rollback := make(chan struct{})
	defer close(rollback)

	tx.OnRollback(func(rollbacker ent.Rollbacker) ent.Rollbacker {
		rollback <- struct{}{}
		return rollbacker
	})

	trigger := make(chan struct{})
	defer close(trigger)

	timeout := 200 * time.Millisecond
	provider := NewTxProviderWithTimeout(&SlowTxProvider{tx: tx, trigger: trigger}, &timeout)

	_, err = provider.GetOrBeginTx(ctx)
	require.ErrorIs(t, err, ErrTxBeginTimeout)

	// Now have the slow provider return the transaction.
	select {
	case trigger <- struct{}{}:
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for the slow provider to trigger")
	}

	select {
	case <-rollback:
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for the rollback to complete")
	}
}

func TestTxProviderWithTimeout_NoTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbClient := NewTestSQLiteClient(t)
	defer dbClient.Close()

	tx, err := dbClient.Tx(ctx)
	require.NoError(t, err, "Failed to create a transaction")

	trigger := make(chan struct{})
	defer close(trigger)

	txChan := make(chan *ent.Tx)
	defer close(txChan)

	timeout := 0 * time.Second
	provider := NewTxProviderWithTimeout(&SlowTxProvider{tx: tx, trigger: trigger}, &timeout)

	go func() {
		tx, err := provider.GetOrBeginTx(ctx)
		if err != nil {
			return
		}

		select {
		case txChan <- tx:
		case <-ctx.Done():
		}
	}()

	go func() {
		time.Sleep(200 * time.Millisecond)

		select {
		case trigger <- struct{}{}:
		case <-ctx.Done():
		}

		return
	}()

	select {
	case <-txChan:
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for the transaction to be returned.")
	}
}
