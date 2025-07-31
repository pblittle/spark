package tokens

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sparktokeninternal "github.com/lightsparkdev/spark/proto/spark_token_internal"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	testutil "github.com/lightsparkdev/spark/test_util"
)

func setupInternalSignTokenTestHandler(t *testing.T) (*InternalSignTokenHandler, context.Context, *ent.Tx, func()) {
	t.Helper()

	config, err := testutil.TestConfig()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	ctx, dbCtx := db.NewTestSQLiteContext(t, ctx)
	t.Cleanup(dbCtx.Close)

	tx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)

	handler := &InternalSignTokenHandler{
		config: config,
	}

	cleanup := func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			t.Errorf("rollback failed: %v", rollbackErr)
		}
	}

	return handler, ctx, tx, cleanup
}

func TestExchangeRevocationSecretsShares(t *testing.T) {
	handler, ctx, tx, cleanup := setupInternalSignTokenTestHandler(t)
	defer cleanup()
	testHash := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
		0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
	}
	testTransaction := tx.TokenTransaction.Create().
		SetPartialTokenTransactionHash(testHash).
		SetFinalizedTokenTransactionHash(testHash).
		SetStatus(st.TokenTransactionStatusSigned).
		SaveX(ctx)

	t.Run("fails when no operator shares provided", func(t *testing.T) {
		req := &sparktokeninternal.ExchangeRevocationSecretsSharesRequest{
			OperatorShares: []*sparktokeninternal.OperatorRevocationShares{},
		}

		_, err := handler.ExchangeRevocationSecretsShares(ctx, req)

		assert.ErrorContains(t, err, "no operator shares provided in request")
	})

	t.Run("fails when operator signatures verification fails", func(t *testing.T) {
		req := &sparktokeninternal.ExchangeRevocationSecretsSharesRequest{
			OperatorShares: []*sparktokeninternal.OperatorRevocationShares{
				{
					OperatorIdentityPublicKey: []byte("operator1_pubkey"),
					Shares: []*sparktokeninternal.RevocationSecretShare{
						{
							InputTtxoId: uuid.New().String(),
							SecretShare: []byte("secret1"),
						},
					},
				},
			},
			OperatorTransactionSignatures: []*sparktokeninternal.OperatorTransactionSignature{
				{
					OperatorIdentityPublicKey: []byte("invalid_operator"),
					Signature:                 []byte("invalid_signature"),
				},
			},
			FinalTokenTransactionHash: testTransaction.FinalizedTokenTransactionHash,
			OperatorIdentityPublicKey: []byte("requesting_operator"),
		}

		_, err := handler.ExchangeRevocationSecretsShares(ctx, req)

		require.ErrorContains(t, err, "unable to parse request operator identity public key")
	})
}

func TestGetSecretSharesNotInInput(t *testing.T) {
	handler, ctx, tx, cleanup := setupInternalSignTokenTestHandler(t)
	defer cleanup()

	aliceOperatorPubKey := handler.config.SigningOperatorMap["0000000000000000000000000000000000000000000000000000000000000001"].IdentityPublicKey
	bobOperatorPubKey := handler.config.SigningOperatorMap["0000000000000000000000000000000000000000000000000000000000000002"].IdentityPublicKey
	carolOperatorPubKey := handler.config.SigningOperatorMap["0000000000000000000000000000000000000000000000000000000000000003"].IdentityPublicKey

	aliceSigningKeyshare := tx.SigningKeyshare.Create().
		SetSecretShare([]byte("alice_secret")).
		SetPublicKey([]byte("alice_public_key")).
		SetStatus(st.KeyshareStatusInUse).
		SetPublicShares(map[string][]byte{}).
		SetMinSigners(1).
		SetCoordinatorIndex(1).
		SaveX(ctx)

	bobSigningKeyshare := tx.SigningKeyshare.Create().
		SetSecretShare([]byte("bob_secret")).
		SetPublicKey([]byte("bob_public_key")).
		SetStatus(st.KeyshareStatusInUse).
		SetPublicShares(map[string][]byte{}).
		SetMinSigners(1).
		SetCoordinatorIndex(1).
		SaveX(ctx)

	carolSigningKeyshare := tx.SigningKeyshare.Create().
		SetSecretShare([]byte("carol_secret")).
		SetPublicKey([]byte("carol_public_key")).
		SetStatus(st.KeyshareStatusInUse).
		SetPublicShares(map[string][]byte{}).
		SetMinSigners(1).
		SetCoordinatorIndex(1).
		SaveX(ctx)

	tokenOutputInDb := tx.TokenOutput.Create().
		SetID(uuid.New()).
		SetOwnerPublicKey(aliceOperatorPubKey.Serialize()).
		SetTokenPublicKey(aliceOperatorPubKey.Serialize()).
		SetTokenAmount([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100}).
		SetRevocationKeyshare(aliceSigningKeyshare).
		SetStatus(st.TokenOutputStatusCreatedFinalized).
		SetWithdrawBondSats(1).
		SetWithdrawRelativeBlockLocktime(1).
		SetWithdrawRevocationCommitment([]byte("withdraw_revocation_commitment")).
		SetCreatedTransactionOutputVout(0).
		SetNetwork(st.NetworkRegtest).
		SetTokenIdentifier([]byte("token_identifier")).
		SaveX(ctx)

	tx.TokenPartialRevocationSecretShare.Create().
		SetTokenOutput(tokenOutputInDb).
		SetOperatorIdentityPublicKey(bobOperatorPubKey.Serialize()).
		SetSecretShare(bobSigningKeyshare.SecretShare).
		SaveX(ctx)

	tx.TokenPartialRevocationSecretShare.Create().
		SetTokenOutput(tokenOutputInDb).
		SetOperatorIdentityPublicKey(carolOperatorPubKey.Serialize()).
		SetSecretShare(carolSigningKeyshare.SecretShare).
		SaveX(ctx)

	t.Run("returns empty map when input share map is empty", func(t *testing.T) {
		inputOperatorShareMap := make(map[ShareKey]ShareValue)

		_, err := handler.getSecretSharesNotInInput(ctx, inputOperatorShareMap)

		require.ErrorContains(t, err, "no input operator shares provided")
	})

	t.Run("excludes the revocation secret share if it is in the input", func(t *testing.T) {
		inputOperatorShareMap := make(map[ShareKey]ShareValue)
		inputOperatorShareMap[ShareKey{
			TokenOutputID:             tokenOutputInDb.ID,
			OperatorIdentityPublicKey: aliceOperatorPubKey,
		}] = ShareValue{
			SecretShare:               aliceSigningKeyshare.SecretShare,
			OperatorIdentityPublicKey: aliceOperatorPubKey,
		}

		result, err := handler.getSecretSharesNotInInput(ctx, inputOperatorShareMap)
		require.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, bobSigningKeyshare.SecretShare, result[bobOperatorPubKey][0].SecretShare)
		assert.Equal(t, carolSigningKeyshare.SecretShare, result[carolOperatorPubKey][0].SecretShare)
	})

	t.Run("excludes the partial revocation secret share if it is in the input", func(t *testing.T) {
		inputOperatorShareMap := make(map[ShareKey]ShareValue)
		inputOperatorShareMap[ShareKey{
			TokenOutputID:             tokenOutputInDb.ID,
			OperatorIdentityPublicKey: bobOperatorPubKey,
		}] = ShareValue{
			SecretShare:               bobSigningKeyshare.SecretShare,
			OperatorIdentityPublicKey: bobOperatorPubKey,
		}

		result, err := handler.getSecretSharesNotInInput(ctx, inputOperatorShareMap)
		require.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, aliceSigningKeyshare.SecretShare, result[aliceOperatorPubKey][0].SecretShare)
		assert.Equal(t, carolSigningKeyshare.SecretShare, result[carolOperatorPubKey][0].SecretShare)
	})
}

func TestValidateSecretShareMatchesPublicKey(t *testing.T) {
	t.Run("valid secret share matches public key", func(t *testing.T) {
		privKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		pubKey := privKey.PubKey()

		secretShareBytes := privKey.Serialize()
		publicKeyBytes := pubKey.SerializeCompressed()

		err = validateSecretShareMatchesPublicKey(secretShareBytes, publicKeyBytes)
		require.NoError(t, err)
	})

	t.Run("throws error when secret share does not match public key", func(t *testing.T) {
		privKey1, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		privKey2, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		secretShareBytes := privKey1.Serialize()
		publicKeyBytes := privKey2.PubKey().SerializeCompressed()

		err = validateSecretShareMatchesPublicKey(secretShareBytes, publicKeyBytes)
		require.ErrorContains(t, err, "secret share:")
		require.ErrorContains(t, err, "does not match public key:")
	})

	t.Run("throws error when public key bytes are invalid", func(t *testing.T) {
		privKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		secretShareBytes := privKey.Serialize()
		invalidPublicKeyBytes := []byte{0x01, 0x02, 0x03}

		err = validateSecretShareMatchesPublicKey(secretShareBytes, invalidPublicKeyBytes)
		require.ErrorContains(t, err, "failed to parse public key:")
	})

	t.Run("throws error when public key bytes are empty", func(t *testing.T) {
		privKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		secretShareBytes := privKey.Serialize()
		var emptyPublicKeyBytes []byte

		err = validateSecretShareMatchesPublicKey(secretShareBytes, emptyPublicKeyBytes)
		require.ErrorContains(t, err, "failed to parse public key:")
	})

	t.Run("throws error when secret share byte array is not 32 bytes in length", func(t *testing.T) {
		privKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		tooShortSecretShareBytes := []byte{0x01}
		tooLongSecretShareBytes := make([]byte, 33)
		wayTooLongSecretShareBytes := make([]byte, 65)
		publicKeyBytes := privKey.PubKey().SerializeCompressed()

		err = validateSecretShareMatchesPublicKey(tooShortSecretShareBytes, publicKeyBytes)
		require.ErrorContains(t, err, "secret share must be 32 bytes")

		err = validateSecretShareMatchesPublicKey(tooLongSecretShareBytes, publicKeyBytes)
		require.ErrorContains(t, err, "secret share must be 32 bytes")

		err = validateSecretShareMatchesPublicKey(wayTooLongSecretShareBytes, publicKeyBytes)
		require.ErrorContains(t, err, "secret share must be 32 bytes")
	})

	t.Run("uncompressed public key format", func(t *testing.T) {
		privKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		pubKey := privKey.PubKey()

		secretShareBytes := privKey.Serialize()
		publicKeyBytes := pubKey.SerializeUncompressed()

		err = validateSecretShareMatchesPublicKey(secretShareBytes, publicKeyBytes)
		require.NoError(t, err)
	})

	t.Run("valid known secret share", func(t *testing.T) {
		secretHex := "076f9db936edeaf93d5bb927fb48891421a6241023a451995f71e3283420ce31"
		secretBytes, err := hex.DecodeString(secretHex)
		require.NoError(t, err)

		pubKeyBase64 := "AwsfmIPOldrBkOQv9FISbbyIjVCLEoFy2+0hiAwV0U/I"
		pubKeyBytes, err := base64.RawStdEncoding.DecodeString(pubKeyBase64)
		require.NoError(t, err)

		err = validateSecretShareMatchesPublicKey(secretBytes, pubKeyBytes)
		require.NoError(t, err)
	})
}
