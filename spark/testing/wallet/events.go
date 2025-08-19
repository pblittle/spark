package wallet

import (
	"context"
	"fmt"

	pb "github.com/lightsparkdev/spark/proto/spark"
)

func SubscribeToEvents(ctx context.Context, config *TestWalletConfig) (pb.SparkService_SubscribeToEventsClient, error) {
	sparkConn, err := config.NewCoordinatorGRPCConnection()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to coordinator: %w", err)
	}
	// Note: We don't defer close here because the stream needs the connection
	sparkClient := pb.NewSparkServiceClient(sparkConn)

	return sparkClient.SubscribeToEvents(ctx, &pb.SubscribeToEventsRequest{
		IdentityPublicKey: config.IdentityPublicKey().Serialize(),
	})
}
