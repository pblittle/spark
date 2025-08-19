package grpc

import (
	"context"

	"github.com/lightsparkdev/spark/common/logging"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	"google.golang.org/grpc"
)

// DatabaseSessionMiddleware is a middleware to manage database sessions for each gRPC call.
func DatabaseSessionMiddleware(factory db.SessionFactory) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if info != nil &&
			(info.FullMethod == "/grpc.health.v1.Health/Check") {
			return handler(ctx, req)
		}

		logger := logging.GetLoggerFromContext(ctx)

		if metricAttrs := ParseFullMethod(info.FullMethod); metricAttrs != nil {
			ctx = db.WithMetricAttributes(ctx, metricAttrs)
		}

		sessionCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		// Start a transaction or session
		session := factory.NewSession(sessionCtx)

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
		if err != nil {
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

		return resp, nil
	}
}
