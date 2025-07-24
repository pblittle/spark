package secretsharing_test

import (
	"crypto/rand"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secretsharing "github.com/lightsparkdev/spark/common/secret_sharing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretSharing(t *testing.T) {
	fieldModulus := secp256k1.S256().N
	secret, err := rand.Int(rand.Reader, fieldModulus)
	require.NoError(t, err)

	threshold := 3
	numberOfShares := 5

	shares, err := secretsharing.SplitSecretWithProofs(secret, fieldModulus, threshold, numberOfShares)
	require.NoError(t, err)

	for _, share := range shares {
		err := secretsharing.ValidateShare(share)
		require.NoError(t, err)
	}

	recoveredSecret, err := secretsharing.RecoverSecret(shares[:threshold])
	require.NoError(t, err)

	assert.Zero(t, secret.Cmp(recoveredSecret), "secret %s does not match recovered secret %s", secret.String(), recoveredSecret.String())
}

func TestSecretSharingBadPubkeyLen(t *testing.T) {
	fieldModulus := secp256k1.S256().N
	secret, err := rand.Int(rand.Reader, fieldModulus)
	require.NoError(t, err)

	threshold := 3
	numberOfShares := 1

	shares, err := secretsharing.SplitSecretWithProofs(secret, fieldModulus, threshold, numberOfShares)
	require.NoError(t, err)
	require.Len(t, shares, 1, "expected one share to be returned")

	share := shares[0]
	share.Proofs[0] = share.Proofs[0][:32]

	err = secretsharing.ValidateShare(share)
	require.Error(t, err, "expected error")
	assert.ErrorContains(t, err, "pubkeys must be 33 bytes")
}
