package helper

import (
	"context"
	"fmt"

	"github.com/lightsparkdev/spark/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so/ent"
)

func TweakLeafKey(ctx context.Context, leaf *ent.TreeNode, req *pb.SendLeafKeyTweak, updatedCpfpRefundTx []byte, updatedDirectRefundTx []byte, updatedDirectFromCpfpRefundTx []byte) error {
	// Tweak keyshare
	keyshare, err := leaf.QuerySigningKeyshare().First(ctx)
	if err != nil || keyshare == nil {
		return fmt.Errorf("unable to load keyshare for leaf %s: %w", req.LeafId, err)
	}
	keyshareID := keyshare.ID.String()

	if req.SecretShareTweak == nil {
		return fmt.Errorf("secret share tweak is not provided for leaf %s", req.LeafId)
	}

	keyshare, err = keyshare.TweakKeyShare(
		ctx,
		req.SecretShareTweak.SecretShare,
		req.SecretShareTweak.Proofs[0],
		req.PubkeySharesTweak,
	)
	if err != nil || keyshare == nil {
		return fmt.Errorf("unable to tweak keyshare %s for leaf %s: %w", keyshareID, req.LeafId, err)
	}

	// Update leaf
	signingPubkey, err := common.SubtractPublicKeys(leaf.VerifyingPubkey, keyshare.PublicKey)
	if err != nil {
		return fmt.Errorf("unable to calculate new signing pubkey for leaf %s: %w", req.LeafId, err)
	}
	leafMutator := leaf.
		Update().
		SetOwnerSigningPubkey(signingPubkey)
	if updatedCpfpRefundTx != nil {
		leafMutator.SetRawRefundTx(updatedCpfpRefundTx)
	}
	if updatedDirectRefundTx != nil {
		leafMutator.SetDirectRefundTx(updatedDirectRefundTx)
	}
	if updatedDirectFromCpfpRefundTx != nil {
		leafMutator.SetDirectFromCpfpRefundTx(updatedDirectFromCpfpRefundTx)
	}
	leaf, err = leafMutator.Save(ctx)
	if err != nil || leaf == nil {
		return fmt.Errorf("unable to update leaf %s: %w", req.LeafId, err)
	}
	return nil
}
