package authninternal

import (
	"math/rand/v2"
	"testing"

	"github.com/lightsparkdev/spark/common/keys"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var seededRand = rand.NewChaCha8([32]byte{})

func TestSessionTokenCreatorVerifier_VerifyToken_InvalidBase64(t *testing.T) {
	identityKey := keys.MustGeneratePrivateKeyFromRand(seededRand)
	verifier, err := NewSessionTokenCreatorVerifier(identityKey, RealClock{})
	require.NoError(t, err)

	session, err := verifier.VerifyToken("not-base64!@#$")

	require.ErrorIs(t, err, ErrInvalidTokenEncoding)
	assert.Nil(t, session)
}

func TestSessionTokenCreatorVerifier_VerifyToken_ValidBase64InvalidProtobuf(t *testing.T) {
	identityKey := keys.MustGeneratePrivateKeyFromRand(seededRand)
	verifier, err := NewSessionTokenCreatorVerifier(identityKey, RealClock{})
	require.NoError(t, err)

	session, err := verifier.VerifyToken("SGVsbG8gV29ybGQ=") // "Hello World" in base64

	require.Error(t, err)
	assert.Nil(t, session)
}
