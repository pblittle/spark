package helper_test

import (
	"math/rand/v2"
	"testing"

	"github.com/lightsparkdev/spark/common/keys"

	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"

	"github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/helper"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTweakLeafKey(t *testing.T) {
	ctx, client := db.NewTestSQLiteContext(t, t.Context())
	defer client.Close()
	dbTx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)
	rng := rand.NewChaCha8([32]byte{})

	// Generate deterministic keys for the test
	ownerPub := keys.MustGeneratePrivateKeyFromRand(rng).Public()
	baseTxid := make([]byte, 32)
	_, _ = rng.Read(baseTxid)

	keysharePriv := keys.MustGeneratePrivateKeyFromRand(rng)
	keysharePub := keysharePriv.Public()
	pubSharePub := keys.MustGeneratePrivateKeyFromRand(rng).Public()
	verifyingPub := keys.MustGeneratePrivateKeyFromRand(rng).Public()
	ownerSigningPub := keys.MustGeneratePrivateKeyFromRand(rng).Public()
	tweakPriv := keys.MustGeneratePrivateKeyFromRand(rng)
	tweakPub := tweakPriv.Public()
	pubkeyShareTweakPub := keys.MustGeneratePrivateKeyFromRand(rng).Public()

	tree, err := dbTx.Tree.Create().
		SetOwnerIdentityPubkey(ownerPub.Serialize()).
		SetStatus(schematype.TreeStatusAvailable).
		SetNetwork(schematype.NetworkMainnet).
		SetBaseTxid(baseTxid).
		SetVout(0).
		Save(ctx)
	require.NoError(t, err)

	keyshare, err := dbTx.SigningKeyshare.Create().
		SetStatus(schematype.KeyshareStatusInUse).
		SetSecretShare(keysharePriv.Serialize()).
		SetPublicShares(map[string][]byte{"operator1": pubSharePub.Serialize()}).
		SetPublicKey(keysharePub.Serialize()).
		SetMinSigners(2).
		SetCoordinatorIndex(1).
		Save(ctx)
	require.NoError(t, err)

	leaf, err := dbTx.TreeNode.Create().
		SetTree(tree).
		SetValue(1000).
		SetStatus(schematype.TreeNodeStatusAvailable).
		SetVerifyingPubkey(verifyingPub.Serialize()).
		SetOwnerIdentityPubkey(ownerPub.Serialize()).
		SetOwnerSigningPubkey(ownerSigningPub.Serialize()).
		SetRawTx(baseTxid).
		SetVout(0).
		SetSigningKeyshare(keyshare).
		Save(ctx)
	require.NoError(t, err)

	req := &spark.SendLeafKeyTweak{
		LeafId: leaf.ID.String(),
		SecretShareTweak: &spark.SecretShare{
			SecretShare: tweakPriv.Serialize(),
			Proofs:      [][]byte{tweakPub.Serialize()},
		},
		PubkeySharesTweak: map[string][]byte{
			"operator1": pubkeyShareTweakPub.Serialize(),
		},
	}

	treeNodeUpdate, err := helper.TweakLeafKeyUpdate(ctx, leaf, req)
	require.NoError(t, err)

	err = treeNodeUpdate.Exec(ctx)
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
	expectedNewSecretShare := keysharePriv.Add(tweakPriv)
	assert.Equal(t, expectedNewSecretShare.Serialize(), updatedKeyshare.SecretShare)

	// The new public key should be the sum of the original and tweak public key
	expectedNewPublicKey := keysharePub.Add(tweakPub)
	assert.Equal(t, expectedNewPublicKey.Serialize(), updatedKeyshare.PublicKey)

	// The new public shares should be the sum of the original and tweak public shares
	expectedNewPublicShares := make(map[string][]byte)
	for operator, originalShare := range keyshare.PublicShares {
		shareKey, err := keys.ParsePublicKey(originalShare)
		require.NoError(t, err)
		expectedNewPublicShares[operator] = shareKey.Add(pubkeyShareTweakPub).Serialize()
	}
	assert.Equal(t, expectedNewPublicShares, updatedKeyshare.PublicShares)
}
