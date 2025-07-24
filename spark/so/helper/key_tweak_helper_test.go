package helper_test

import (
	"context"
	"testing"

	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/helper"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateFixedKeyPair returns a deterministic secp256k1 keypair based on a fixed seed and a unique index.
func generateFixedKeyPair(idx byte) (privKey32 []byte, pubKey33 []byte) {
	seed := [32]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, idx,
	}
	priv := secp256k1.PrivKeyFromBytes(seed[:])
	return priv.Serialize(), priv.PubKey().SerializeCompressed()
}

func TestTweakLeafKey_Success(t *testing.T) {
	ctx, client := db.NewTestSQLiteContext(t, context.Background())
	defer client.Close()
	dbTx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)

	// Generate deterministic keys for the test
	_, ownerPub := generateFixedKeyPair(1)
	baseTxid, _ := generateFixedKeyPair(2)
	keysharePriv, keysharePub := generateFixedKeyPair(3)
	_, pubSharePub := generateFixedKeyPair(4)
	_, verifyingPub := generateFixedKeyPair(5)
	_, ownerSigningPub := generateFixedKeyPair(6)
	tweakPriv, tweakPub := generateFixedKeyPair(7)
	_, pubkeyShareTweakPub := generateFixedKeyPair(8)

	tree, err := dbTx.Tree.Create().
		SetOwnerIdentityPubkey(ownerPub).
		SetStatus(schematype.TreeStatusAvailable).
		SetNetwork(schematype.NetworkMainnet).
		SetBaseTxid(baseTxid).
		SetVout(0).
		Save(ctx)
	require.NoError(t, err)

	keyshare, err := dbTx.SigningKeyshare.Create().
		SetStatus(schematype.KeyshareStatusInUse).
		SetSecretShare(keysharePriv).
		SetPublicShares(map[string][]byte{"operator1": pubSharePub}).
		SetPublicKey(keysharePub).
		SetMinSigners(2).
		SetCoordinatorIndex(1).
		Save(ctx)
	require.NoError(t, err)

	leaf, err := dbTx.TreeNode.Create().
		SetTree(tree).
		SetValue(1000).
		SetStatus(schematype.TreeNodeStatusAvailable).
		SetVerifyingPubkey(verifyingPub).
		SetOwnerIdentityPubkey(ownerPub).
		SetOwnerSigningPubkey(ownerSigningPub).
		SetRawTx(baseTxid).
		SetVout(0).
		SetSigningKeyshare(keyshare).
		Save(ctx)
	require.NoError(t, err)

	req := &spark.SendLeafKeyTweak{
		LeafId: leaf.ID.String(),
		SecretShareTweak: &spark.SecretShare{
			SecretShare: tweakPriv,
			Proofs:      [][]byte{tweakPub},
		},
		PubkeySharesTweak: map[string][]byte{
			"operator1": pubkeyShareTweakPub,
		},
	}

	err = helper.TweakLeafKey(ctx, leaf, req, nil, nil, nil)
	require.NoError(t, err)

	err = dbTx.Commit()
	require.NoError(t, err)

	updatedLeaf, err := client.Client.TreeNode.Get(ctx, leaf.ID)
	require.NoError(t, err)
	assert.NotNil(t, updatedLeaf)

	updatedKeyshare, err := client.Client.SigningKeyshare.Get(ctx, keyshare.ID)
	require.NoError(t, err)
	assert.NotNil(t, updatedKeyshare)

	// Verify that the keyshare was properly updated with the tweak values
	// The new secret share should be the sum of the original and tweak
	expectedNewSecretShare, err := common.AddPrivateKeys(keysharePriv, tweakPriv)
	require.NoError(t, err)
	assert.Equal(t, expectedNewSecretShare, updatedKeyshare.SecretShare)

	// The new public key should be the sum of the original and tweak public key
	expectedNewPublicKey, err := common.AddPublicKeys(keysharePub, tweakPub)
	require.NoError(t, err)
	assert.Equal(t, expectedNewPublicKey, updatedKeyshare.PublicKey)

	// The new public shares should be the sum of the original and tweak public shares
	expectedNewPublicShares := make(map[string][]byte)
	for operator, originalShare := range keyshare.PublicShares {
		expectedNewShare, err := common.AddPublicKeys(originalShare, pubkeyShareTweakPub)
		require.NoError(t, err)
		expectedNewPublicShares[operator] = expectedNewShare
	}
	assert.Equal(t, expectedNewPublicShares, updatedKeyshare.PublicShares)
}

func TestTweakLeafKey_WithRefundTx(t *testing.T) {
	ctx, client := db.NewTestSQLiteContext(t, context.Background())
	defer client.Close()
	dbTx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)

	// Generate deterministic keys for the test
	_, ownerPub := generateFixedKeyPair(11)
	baseTxid, _ := generateFixedKeyPair(12)
	keysharePriv, keysharePub := generateFixedKeyPair(13)
	_, pubSharePub := generateFixedKeyPair(14)
	_, verifyingPub := generateFixedKeyPair(15)
	_, ownerSigningPub := generateFixedKeyPair(16)
	tweakPriv, tweakPub := generateFixedKeyPair(17)
	_, pubkeyShareTweakPub := generateFixedKeyPair(18)

	tree, err := dbTx.Tree.Create().
		SetOwnerIdentityPubkey(ownerPub).
		SetStatus(schematype.TreeStatusAvailable).
		SetNetwork(schematype.NetworkMainnet).
		SetBaseTxid(baseTxid).
		SetVout(0).
		Save(ctx)
	require.NoError(t, err)

	keyshare, err := dbTx.SigningKeyshare.Create().
		SetStatus(schematype.KeyshareStatusInUse).
		SetSecretShare(keysharePriv).
		SetPublicShares(map[string][]byte{"operator1": pubSharePub}).
		SetPublicKey(keysharePub).
		SetMinSigners(2).
		SetCoordinatorIndex(1).
		Save(ctx)
	require.NoError(t, err)

	leaf, err := dbTx.TreeNode.Create().
		SetTree(tree).
		SetValue(1000).
		SetStatus(schematype.TreeNodeStatusAvailable).
		SetVerifyingPubkey(verifyingPub).
		SetOwnerIdentityPubkey(ownerPub).
		SetOwnerSigningPubkey(ownerSigningPub).
		SetRawTx(baseTxid).
		SetVout(0).
		SetSigningKeyshare(keyshare).
		Save(ctx)
	require.NoError(t, err)

	req := &spark.SendLeafKeyTweak{
		LeafId: leaf.ID.String(),
		SecretShareTweak: &spark.SecretShare{
			SecretShare: tweakPriv,
			Proofs:      [][]byte{tweakPub},
		},
		PubkeySharesTweak: map[string][]byte{
			"operator1": pubkeyShareTweakPub,
		},
	}

	cpfpRefundTx := make([]byte, 100)
	directRefundTx := make([]byte, 100)
	directFromCpfpLeafRefundTx := make([]byte, 100)
	err = helper.TweakLeafKey(ctx, leaf, req, cpfpRefundTx, directRefundTx, directFromCpfpLeafRefundTx)
	require.NoError(t, err)

	err = dbTx.Commit()
	require.NoError(t, err)

	updatedLeaf, err := client.Client.TreeNode.Get(ctx, leaf.ID)
	require.NoError(t, err)
	assert.NotNil(t, updatedLeaf)
	assert.Equal(t, cpfpRefundTx, updatedLeaf.RawRefundTx)
	assert.Equal(t, directRefundTx, updatedLeaf.DirectRefundTx)
	assert.Equal(t, directFromCpfpLeafRefundTx, updatedLeaf.DirectFromCpfpRefundTx)
}
