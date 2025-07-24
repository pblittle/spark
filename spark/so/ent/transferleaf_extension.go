package ent

import (
	"context"
	"fmt"

	pb "github.com/lightsparkdev/spark/proto/spark"
)

// MarshalProto converts a Transfer to a spark protobuf Transfer.
func (t *TransferLeaf) MarshalProto(ctx context.Context) (*pb.TransferLeaf, error) {
	leaf, err := t.QueryLeaf().Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to query leaf for transfer leaf %s: %w", t.ID.String(), err)
	}
	leafProto, err := leaf.MarshalSparkProto(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal leaf  %s: %w", leaf.ID.String(), err)
	}
	return &pb.TransferLeaf{
		Leaf:                               leafProto,
		SecretCipher:                       t.SecretCipher,
		Signature:                          t.Signature,
		IntermediateRefundTx:               t.IntermediateRefundTx,
		IntermediateDirectRefundTx:         t.IntermediateDirectRefundTx,
		IntermediateDirectFromCpfpRefundTx: t.IntermediateDirectFromCpfpRefundTx,
	}, nil
}
