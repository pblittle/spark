package events

import (
	"context"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/lightsparkdev/spark/common/keys"

	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type MockStream struct {
	ctx      context.Context
	messages []*pb.SubscribeToEventsResponse
	mu       sync.Mutex
	sendErr  error
}

func NewMockStream(t *testing.T) *MockStream {
	return &MockStream{
		ctx:      t.Context(),
		messages: make([]*pb.SubscribeToEventsResponse, 0),
	}
}

func (m *MockStream) Send(msg *pb.SubscribeToEventsResponse) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, msg)
	return nil
}

func (m *MockStream) RecvMsg(_ any) error {
	return nil
}

func (m *MockStream) Context() context.Context {
	return m.ctx
}

func (m *MockStream) SendHeader(_ metadata.MD) error {
	return nil
}

func (m *MockStream) SendMsg(_ any) error {
	return nil
}

func (m *MockStream) SetHeader(_ metadata.MD) error {
	return nil
}

func (m *MockStream) SetTrailer(_ metadata.MD) {}

func TestEventRouterConcurrency(t *testing.T) {
	router := NewEventRouter()
	rng := rand.NewChaCha8([32]byte{})
	identityKey := keys.MustGeneratePrivateKeyFromRand(rng).Public()

	const numGoroutines = 100
	var wg sync.WaitGroup

	makeStream := func(i int) *MockStream {
		switch i % 3 {
		case 0:
			// Normal stream
			return NewMockStream(t)
		case 1:
			// Stream that errors on send
			return &MockStream{
				ctx:     t.Context(),
				sendErr: status.Error(codes.Unavailable, "stream closed"),
			}
		default:
			// Stream with cancellable context
			ctx, cancel := context.WithCancel(t.Context())
			stream := &MockStream{ctx: ctx}
			// Cancel after a short delay
			go func() {
				time.Sleep(time.Millisecond)
				cancel()
			}()
			return stream
		}
	}

	for i := range numGoroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			stream := makeStream(idx)
			err := router.RegisterStream(identityKey, stream)
			if err != nil {
				t.Errorf("Failed to register stream: %v", err)
			}
		}(i)
	}

	for range numGoroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg := &pb.SubscribeToEventsResponse{}
			_ = router.NotifyUser(identityKey, msg)
		}()
	}

	wg.Wait()
}

func TestEventRouterLastStreamWins(t *testing.T) {
	router := NewEventRouter()
	rng := rand.NewChaCha8([32]byte{})
	identityKey := keys.MustGeneratePrivateKeyFromRand(rng).Public()

	stream1 := NewMockStream(t)
	stream2 := NewMockStream(t)
	stream3 := NewMockStream(t)

	err := router.RegisterStream(identityKey, stream1)
	require.NoError(t, err)
	err = router.RegisterStream(identityKey, stream2)
	require.NoError(t, err)
	err = router.RegisterStream(identityKey, stream3)
	require.NoError(t, err)

	testMsg := &pb.SubscribeToEventsResponse{}
	_ = router.NotifyUser(identityKey, testMsg)

	if len(stream1.messages) > 0 || len(stream2.messages) > 0 {
		t.Error("Previous streams should not receive messages")
	}
	if len(stream3.messages) == 0 {
		t.Error("Last stream should receive messages")
	}
}
