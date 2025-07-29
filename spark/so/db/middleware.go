package db

import (
	"context"
	"errors"

	"github.com/lightsparkdev/spark/common/logging"
	"github.com/lightsparkdev/spark/so/ent"
	"google.golang.org/grpc"
)

// ErrNoRollback is an error indicating that we should not roll back the DB transaction.
var ErrNoRollback = errors.New("no rollback performed")

// SessionMiddleware is a middleware to manage database sessions for each gRPC call.
func SessionMiddleware(factory SessionFactory) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if info != nil &&
			(info.FullMethod == "/grpc.health.v1.Health/Check" || info.FullMethod == "/spark.SparkService/query_token_outputs") {
			return handler(ctx, req)
		}

		logger := logging.GetLoggerFromContext(ctx)

		// Start a transaction or session
		session := factory.NewSession()

		// Attach the transaction to the context
		ctx = ent.Inject(ctx, session)
		// Ensure rollback on panic
		defer func() {
			if r := recover(); r != nil {
				if tx := session.GetTxIfExists(); tx != nil {
					if dberr := tx.Rollback(); dberr != nil {
						logger.Error("Failed to rollback transaction", "error", dberr)
					}
					logger.Info("Transaction rolled back")
				}
				panic(r)
			}
		}()

		// Call the handler (the actual RPC method)
		resp, err := handler(ctx, req)

		// Handle transaction commit/rollback
		if err != nil && !errors.Is(err, ErrNoRollback) {
			logger.Info("Rolling back transaction")
			if tx := session.GetTxIfExists(); tx != nil {
				if dberr := tx.Rollback(); dberr != nil {
					logger.Error("Failed to rollback transaction", "error", dberr)
				}
			}
			logger.Info("Transaction rolled back")
			return nil, err
		}

		if tx := session.GetTxIfExists(); tx != nil {
			logger.Info("Committing transaction")
			if dberr := tx.Commit(); dberr != nil {
				logger.Error("Failed to commit transaction", "error", dberr)
				return nil, dberr
			}
			logger.Info("Transaction committed")
		}

		if errors.Is(err, ErrNoRollback) {
			logger.Debug("Skipping rollback", "error", err)
			return nil, err
		}

		return resp, nil
	}
}
