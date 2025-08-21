package events

import (
	"fmt"
	"sync"

	"github.com/lightsparkdev/spark/common/keys"

	pb "github.com/lightsparkdev/spark/proto/spark"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var (
	defaultRouter *EventRouter
	routerOnce    sync.Once
)

func GetDefaultRouter() *EventRouter {
	routerOnce.Do(func() {
		defaultRouter = NewEventRouter()
	})
	return defaultRouter
}

type EventRouter struct {
	streams sync.Map
	mutexes sync.Map
}

func NewEventRouter() *EventRouter {
	return &EventRouter{
		streams: sync.Map{},
		mutexes: sync.Map{},
	}
}

func (s *EventRouter) RegisterStream(identityPublicKey keys.Public, stream pb.SparkService_SubscribeToEventsServer) error {
	mutex, _ := s.mutexes.LoadOrStore(identityPublicKey, &sync.Mutex{})
	mutex.(*sync.Mutex).Lock()
	defer mutex.(*sync.Mutex).Unlock()

	s.streams.Store(identityPublicKey, stream)
	go func() {
		<-stream.Context().Done()
		if mutex, ok := s.mutexes.Load(identityPublicKey); ok {
			mutex.(*sync.Mutex).Lock()
			defer mutex.(*sync.Mutex).Unlock()

			if current, ok := s.streams.Load(identityPublicKey); ok {
				if current.(pb.SparkService_SubscribeToEventsServer) == stream {
					s.streams.Delete(identityPublicKey)
					s.mutexes.Delete(identityPublicKey)
				}
			}
		}
	}()

	return nil
}

func (s *EventRouter) NotifyUser(identityPublicKey keys.Public, message *pb.SubscribeToEventsResponse) error {
	mutex, ok := s.mutexes.Load(identityPublicKey)
	if !ok || mutex == nil {
		return nil
	}
	mutex.(*sync.Mutex).Lock()
	defer mutex.(*sync.Mutex).Unlock()

	if currentStream, ok := s.streams.Load(identityPublicKey); ok {
		if err := currentStream.(pb.SparkService_SubscribeToEventsServer).Send(message); err != nil {
			s.streams.Delete(identityPublicKey)
			s.mutexes.Delete(identityPublicKey)

			if !isStreamClosedError(err) {
				network := "unknown"
				address := "unknown"
				if ctxPeer, ok := peer.FromContext(currentStream.(pb.SparkService_SubscribeToEventsServer).Context()); ok {
					network = ctxPeer.Addr.Network()
					address = ctxPeer.Addr.String()
				}

				return fmt.Errorf("error sending message to stream for (network: %s, address: %s): %w", network, address, err)
			}
		}
	}

	return nil
}

func SubscribeToEvents(identityPublicKey keys.Public, st pb.SparkService_SubscribeToEventsServer) error {
	streamRouter := GetDefaultRouter()
	if err := streamRouter.RegisterStream(identityPublicKey, st); err != nil {
		return err
	}

	connectedEvent := &pb.SubscribeToEventsResponse{
		Event: &pb.SubscribeToEventsResponse_Connected{
			Connected: &pb.ConnectedEvent{},
		},
	}

	if err := streamRouter.NotifyUser(identityPublicKey, connectedEvent); err != nil {
		return err
	}

	<-st.Context().Done()
	return nil
}

func isStreamClosedError(err error) bool {
	if err == nil {
		return false
	}

	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Canceled, codes.Unavailable, codes.DeadlineExceeded:
			return true
		default:
			return false
		}
	}

	return false
}
