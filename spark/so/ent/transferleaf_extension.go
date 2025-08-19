package ent

import (
	"context"
	"fmt"

	pb "github.com/lightsparkdev/spark/proto/spark"
	"google.golang.org/protobuf/proto"
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
	var keyTweakProof []byte
	secretCipher := t.SecretCipher
	signature := t.Signature
	if t.KeyTweak != nil {
		leafKeyTweak := &pb.SendLeafKeyTweak{}
		err = proto.Unmarshal(t.KeyTweak, leafKeyTweak)
		if err == nil {
			keyTweakProof = leafKeyTweak.SecretShareTweak.Proofs[0]
			if len(secretCipher) == 0 {
				secretCipher = leafKeyTweak.SecretCipher
			}
			if len(signature) == 0 {
				signature = leafKeyTweak.Signature
			}
		}
	}

	return &pb.TransferLeaf{
		Leaf:                               leafProto,
		SecretCipher:                       secretCipher,
		Signature:                          signature,
		IntermediateRefundTx:               t.IntermediateRefundTx,
		IntermediateDirectRefundTx:         t.IntermediateDirectRefundTx,
		IntermediateDirectFromCpfpRefundTx: t.IntermediateDirectFromCpfpRefundTx,
		PendingKeyTweakPublicKey:           keyTweakProof,
	}, nil
}
