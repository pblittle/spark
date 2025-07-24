package grpc

import (
	"context"

	pbgossip "github.com/lightsparkdev/spark/proto/gossip"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/errors"
	"github.com/lightsparkdev/spark/so/handler"
	"google.golang.org/protobuf/types/known/emptypb"
)

type GossipServer struct {
	pbgossip.UnimplementedGossipServiceServer
	config *so.Config
}

func NewGossipServer(config *so.Config) *GossipServer {
	return &GossipServer{config: config}
}

func (s *GossipServer) Gossip(ctx context.Context, req *pbgossip.GossipMessage) (*emptypb.Empty, error) {
	gossipHandler := handler.NewGossipHandler(s.config)
	return errors.WrapWithGRPCError(&emptypb.Empty{}, gossipHandler.HandleGossipMessage(ctx, req, false))
}
