package grpctest

import (
	"context"
	"testing"
	"time"

	"github.com/lightsparkdev/spark/common/keys"

	pb "github.com/lightsparkdev/spark/proto/spark"
	testutil "github.com/lightsparkdev/spark/test_util"
	"github.com/lightsparkdev/spark/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func skipConnectedEvent(t *testing.T, stream pb.SparkService_SubscribeToEventsClient) {
	event, err := stream.Recv()
	if err != nil {
		t.Errorf("failed to receive event: %v", err) // We have to do this instead of require since this is a goroutine
	}
	assert.NotNil(t, event.GetConnected())
}

func TestEventHandlerTransferNotification(t *testing.T) {
	senderConfig, err := testutil.TestWalletConfig()
	require.NoError(t, err)

	receiverConfig, err := testutil.TestWalletConfig()
	require.NoError(t, err)

	stream, err := wallet.SubscribeToEvents(context.Background(), receiverConfig)
	require.NoError(t, err)

	numTransfers := 5
	events := make(chan *pb.SubscribeToEventsResponse, numTransfers)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		skipConnectedEvent(t, stream)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				event, err := stream.Recv()
				if err != nil {
					return
				}
				events <- event
			}
		}
	}()

	var expectedNodeIDs []string
	for range numTransfers {
		leafPrivKey, err := keys.GeneratePrivateKey()
		require.NoError(t, err, "failed to create node signing private key")

		rootNode, err := testutil.CreateNewTree(senderConfig, faucet, leafPrivKey, 100_000)
		require.NoError(t, err, "failed to create new tree")
		expectedNodeIDs = append(expectedNodeIDs, rootNode.Id)

		newLeafPrivKey, err := keys.GeneratePrivateKey()
		require.NoError(t, err, "failed to create new node signing private key")

		transferNode := wallet.LeafKeyTweak{
			Leaf:              rootNode,
			SigningPrivKey:    leafPrivKey,
			NewSigningPrivKey: newLeafPrivKey,
		}
		leavesToTransfer := [1]wallet.LeafKeyTweak{transferNode}

		_, err = wallet.SendTransfer(
			context.Background(),
			senderConfig,
			leavesToTransfer[:],
			receiverConfig.IdentityPublicKey(),
			time.Now().Add(10*time.Minute),
		)
		require.NoError(t, err)
	}

	receivedEvents := 0
	receivedNodeIDs := make(map[string]bool)

	for receivedEvents < numTransfers {
		select {
		case event := <-events:
			require.NotNil(t, event)
			require.NotNil(t, event.GetTransfer())
			transfer := event.GetTransfer().Transfer
			require.NotNil(t, transfer)
			require.Len(t, transfer.Leaves, 1)

			nodeID := transfer.Leaves[0].Leaf.Id
			require.Contains(t, expectedNodeIDs, nodeID)
			require.NotContains(t, receivedNodeIDs, nodeID, "Received duplicate event")
			receivedNodeIDs[nodeID] = true
			receivedEvents++

		case <-time.After(10 * time.Second):
			require.Fail(t, "timed out waiting for events")
		}
	}
}

func TestEventHandlerDepositNotification(t *testing.T) {
	config, err := testutil.TestWalletConfig()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream, err := wallet.SubscribeToEvents(ctx, config)
	require.NoError(t, err)

	skipConnectedEvent(t, stream)
	events := make(chan *pb.SubscribeToEventsResponse, 1)
	errors := make(chan error, 1)
	go func() {
		for {
			event, err := stream.Recv()
			if err != nil {
				errors <- err
				return
			}
			events <- event
			return
		}
	}()

	leafPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err, "failed to create node signing private key")

	rootNode, err := testutil.CreateNewTree(config, faucet, leafPrivKey, 100_000)
	require.NoError(t, err, "failed to create new tree")

	select {
	case event := <-events:
		require.NotNil(t, event)
		require.NotNil(t, event.GetDeposit())
		require.Equal(t, rootNode.Id, event.GetDeposit().Deposit.Id)
	case err := <-errors:
		t.Fatalf("stream error: %v", err)
	case <-time.After(5 * time.Second):
		require.Fail(t, "no event received")
	}
}

func TestMultipleSubscriptions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	senderConfig, err := testutil.TestWalletConfig()
	require.NoError(t, err)

	receiverConfig, err := testutil.TestWalletConfig()
	require.NoError(t, err)

	stream1, err := wallet.SubscribeToEvents(ctx, receiverConfig)
	require.NoError(t, err)

	events1 := make(chan *pb.SubscribeToEventsResponse)
	go func() {
		defer close(events1)

		for {
			event, err := stream1.Recv()
			if err != nil {
				return
			}

			select {
			case events1 <- event:
			case <-ctx.Done():
			}
		}
	}()

	select {
	case ev := <-events1:
		require.NotNil(t, ev.GetConnected(), "stream1 should receive a connected event")
	case <-time.After(200 * time.Millisecond):
		t.Fatal("stream1 timed out waiting for connected event")
	}

	stream2, err := wallet.SubscribeToEvents(ctx, receiverConfig)
	require.NoError(t, err)

	events2 := make(chan *pb.SubscribeToEventsResponse)
	go func() {
		defer close(events2)

		for {
			event, err := stream2.Recv()
			if err != nil {
				return
			}

			select {
			case events2 <- event:
			case <-ctx.Done():
			}
		}
	}()

	select {
	case ev := <-events2:
		require.NotNil(t, ev.GetConnected(), "stream2 should receive a connected event")
	case <-time.After(200 * time.Millisecond):
		t.Fatal("stream2 timed out waiting for connected event")
	}

	leafPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	rootNode, err := testutil.CreateNewTree(senderConfig, faucet, leafPrivKey, 100_000)
	require.NoError(t, err)

	newLeafPrivKey, err := keys.GeneratePrivateKey()
	require.NoError(t, err)
	transferNode := wallet.LeafKeyTweak{
		Leaf:              rootNode,
		SigningPrivKey:    leafPrivKey,
		NewSigningPrivKey: newLeafPrivKey,
	}
	leavesToTransfer := [1]wallet.LeafKeyTweak{transferNode}

	_, err = wallet.SendTransfer(
		ctx,
		senderConfig,
		leavesToTransfer[:],
		receiverConfig.IdentityPublicKey(),
		time.Now().Add(10*time.Minute),
	)
	require.NoError(t, err)

	select {
	case ev := <-events1:
		t.Fatalf("stream1 should not receive any events (received %v)", ev)
	case event := <-events2:
		require.NotNil(t, event)
		require.NotNil(t, event.GetTransfer())
		require.Equal(t, rootNode.Id, event.GetTransfer().Transfer.Leaves[0].Leaf.Id)
	case <-time.After(5 * time.Second):
		t.Fatal("no event received on stream2")
	}
}
