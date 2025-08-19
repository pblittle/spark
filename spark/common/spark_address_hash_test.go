package common

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/lightsparkdev/spark/common/keys"
	pb "github.com/lightsparkdev/spark/proto/spark"
)

func TestHashSparkInvoiceFields_TokensBasic(t *testing.T) {
	identityPublicKey, err := hex.DecodeString("02ccb26ba79c63aaf60c9192fd874be3087ae8d8703275df0e558704a6d3a4f132")
	require.NoError(t, err)

	uid, err := uuid.NewV7()
	require.NoError(t, err)
	id := uid[:]

	tokenIdentifier, err := hex.DecodeString("9cef64327b1c1f18eb4b4944fc70a1fe9dd84d9084c7daae751de535baafd49f")
	require.NoError(t, err)

	amount := big.NewInt(1000).Bytes()
	memo := "memo-1"
	expiry := time.Now().Add(2 * time.Hour).UTC()

	network := Regtest
	receiverPublicKey, err := keys.ParsePublicKey(identityPublicKey)
	require.NoError(t, err)

	f1 := CreateTokenSparkInvoiceFields(id, tokenIdentifier, amount, &memo, identityPublicKey, &expiry)

	h1, err := HashSparkInvoiceFields(f1, network, receiverPublicKey)
	require.NoError(t, err)
	require.Len(t, h1, 32)

	// Same values -> same hash
	f2 := CreateTokenSparkInvoiceFields(append([]byte{}, id...), append([]byte{}, tokenIdentifier...), append([]byte{}, amount...), &memo, append([]byte{}, identityPublicKey...), &expiry)
	h2, err := HashSparkInvoiceFields(f2, network, receiverPublicKey)
	require.NoError(t, err)
	require.True(t, bytes.Equal(h1, h2))

	// Change memo -> different hash
	memo2 := "memo-2"
	f3 := CreateTokenSparkInvoiceFields(id, tokenIdentifier, amount, &memo2, identityPublicKey, &expiry)
	h3, err := HashSparkInvoiceFields(f3, network, receiverPublicKey)
	require.NoError(t, err)
	require.False(t, bytes.Equal(h1, h3))
}

func TestHashSparkInvoiceFields_SatsBasic(t *testing.T) {
	identityPublicKey, err := hex.DecodeString("02ccb26ba79c63aaf60c9192fd874be3087ae8d8703275df0e558704a6d3a4f132")
	require.NoError(t, err)

	uid, err := uuid.NewV7()
	require.NoError(t, err)
	id := uid[:]

	var sats uint64 = 1000
	memo := "sats-memo"
	expiry := time.Now().Add(1 * time.Hour).UTC()

	network := Regtest
	receiverPublicKey, err := keys.ParsePublicKey(identityPublicKey)
	require.NoError(t, err)

	f1 := CreateSatsSparkInvoiceFields(id, &sats, &memo, identityPublicKey, &expiry)

	h1, err := HashSparkInvoiceFields(f1, network, receiverPublicKey)
	require.NoError(t, err)
	require.Len(t, h1, 32)

	// Change amount -> different hash
	newsats := uint64(2000)
	f2 := CreateSatsSparkInvoiceFields(id, &newsats, &memo, identityPublicKey, &expiry)
	h2, err := HashSparkInvoiceFields(f2, network, receiverPublicKey)
	require.NoError(t, err)
	require.False(t, bytes.Equal(h1, h2))
}

func TestHashSparkInvoiceFields_InvalidInputs(t *testing.T) {
	identityPublicKey, _ := hex.DecodeString("02ccb26ba79c63aaf60c9192fd874be3087ae8d8703275df0e558704a6d3a4f132")
	uid, _ := uuid.NewV7()
	id := uid[:]
	memo := "m"

	network := Regtest
	receiverPublicKey, err := keys.ParsePublicKey(identityPublicKey)
	require.NoError(t, err)

	// nil fields
	_, err = HashSparkInvoiceFields(nil, network, receiverPublicKey)
	require.Error(t, err)

	// bad id length
	fBadID := CreateSatsSparkInvoiceFields([]byte{1, 2, 3}, nil, &memo, identityPublicKey, nil)
	_, err = HashSparkInvoiceFields(fBadID, network, receiverPublicKey)
	require.Error(t, err)

	// tokens: bad token identifier length (not 32)
	fBadTokenID := CreateTokenSparkInvoiceFields(id, make([]byte, 31), nil, &memo, identityPublicKey, nil)
	_, err = HashSparkInvoiceFields(fBadTokenID, network, receiverPublicKey)
	require.Error(t, err)

	// tokens: amount too large (>16 bytes)
	fBigAmt := CreateTokenSparkInvoiceFields(id, make([]byte, 32), make([]byte, 17), &memo, identityPublicKey, nil)
	_, err = HashSparkInvoiceFields(fBigAmt, network, receiverPublicKey)
	require.Error(t, err)

	// missing payment type
	fMissingPT := &pb.SparkInvoiceFields{Version: 1, Id: id, Memo: &memo, SenderPublicKey: identityPublicKey}
	_, err = HashSparkInvoiceFields(fMissingPT, network, receiverPublicKey)
	require.Error(t, err)

	// sender public key wrong length (must be 33)
	fBadSPK := CreateSatsSparkInvoiceFields(id, nil, &memo, make([]byte, 32), nil)
	_, err = HashSparkInvoiceFields(fBadSPK, network, receiverPublicKey)
	require.Error(t, err)
}

func TestHashSparkInvoiceFields_EmptyAndNilEquivalences(t *testing.T) {
	identityPublicKey, _ := hex.DecodeString("02ccb26ba79c63aaf60c9192fd874be3087ae8d8703275df0e558704a6d3a4f132")
	uid, _ := uuid.NewV7()
	id := uid[:]

	network := Regtest
	receiverPublicKey, err := keys.ParsePublicKey(identityPublicKey)
	require.NoError(t, err)

	// tokens: tokenIdentifier nil vs empty slice
	amt := big.NewInt(123).Bytes()
	memo := ""
	fNilTI := CreateTokenSparkInvoiceFields(id, nil, amt, &memo, identityPublicKey, nil)
	fEmptyTI := CreateTokenSparkInvoiceFields(id, []byte{}, amt, &memo, identityPublicKey, nil)
	h1, err := HashSparkInvoiceFields(fNilTI, network, receiverPublicKey)
	require.NoError(t, err)
	h2, err := HashSparkInvoiceFields(fEmptyTI, network, receiverPublicKey)
	require.NoError(t, err)
	require.True(t, bytes.Equal(h1, h2))

	// tokens: amount nil vs empty slice
	fNilAmt := CreateTokenSparkInvoiceFields(id, make([]byte, 32), nil, &memo, identityPublicKey, nil)
	fEmptyAmt := CreateTokenSparkInvoiceFields(id, make([]byte, 32), []byte{}, &memo, identityPublicKey, nil)
	h3, err := HashSparkInvoiceFields(fNilAmt, network, receiverPublicKey)
	require.NoError(t, err)
	h4, err := HashSparkInvoiceFields(fEmptyAmt, network, receiverPublicKey)
	require.NoError(t, err)
	require.True(t, bytes.Equal(h3, h4))

	// sats: amount nil vs 0
	fNilSats := CreateSatsSparkInvoiceFields(id, nil, &memo, identityPublicKey, nil)
	zero := uint64(0)
	fZeroSats := CreateSatsSparkInvoiceFields(id, &zero, &memo, identityPublicKey, nil)
	h5, err := HashSparkInvoiceFields(fNilSats, network, receiverPublicKey)
	require.NoError(t, err)
	h6, err := HashSparkInvoiceFields(fZeroSats, network, receiverPublicKey)
	require.NoError(t, err)
	require.True(t, bytes.Equal(h5, h6))

	// memo nil vs empty string
	fMemoNil := CreateSatsSparkInvoiceFields(id, &zero, nil, identityPublicKey, nil)
	fMemoEmpty := CreateSatsSparkInvoiceFields(id, &zero, &memo, identityPublicKey, nil)
	h7, err := HashSparkInvoiceFields(fMemoNil, network, receiverPublicKey)
	require.NoError(t, err)
	h8, err := HashSparkInvoiceFields(fMemoEmpty, network, receiverPublicKey)
	require.NoError(t, err)
	require.True(t, bytes.Equal(h7, h8))

	// sender pubkey nil vs empty slice
	fSpkNil := CreateSatsSparkInvoiceFields(id, &zero, nil, nil, nil)
	fSpkEmpty := CreateSatsSparkInvoiceFields(id, &zero, nil, []byte{}, nil)
	h9, err := HashSparkInvoiceFields(fSpkNil, network, receiverPublicKey)
	require.NoError(t, err)
	h10, err := HashSparkInvoiceFields(fSpkEmpty, network, receiverPublicKey)
	require.NoError(t, err)
	require.True(t, bytes.Equal(h9, h10))
}

func TestVerifySparkAddressSignature_Valid(t *testing.T) {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PubKey().SerializeCompressed()

	uid, err := uuid.NewV7()
	require.NoError(t, err)
	id := uid[:]
	memo := "invoice-memo"
	amount := big.NewInt(42).Bytes()

	network := Regtest
	receiverPublicKey, err := keys.ParsePublicKey(pubKey)
	require.NoError(t, err)

	fields := CreateTokenSparkInvoiceFields(id, make([]byte, 32), amount, &memo, pubKey, nil)
	hash, err := HashSparkInvoiceFields(fields, network, receiverPublicKey)
	require.NoError(t, err)

	sig, err := schnorr.Sign(privKey, hash)
	require.NoError(t, err)

	addr := &pb.SparkAddress{
		IdentityPublicKey:  pubKey,
		SparkInvoiceFields: fields,
		Signature:          sig.Serialize(),
	}
	require.NoError(t, VerifySparkAddressSignature(addr, network))
}

func TestVerifySparkAddressSignature_Errors(t *testing.T) {

	t.Run("missing signature", func(t *testing.T) {
		privKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		pubKey := privKey.PubKey().SerializeCompressed()

		network := Regtest

		uid, _ := uuid.NewV7()
		id := uid[:]
		memo := "m"
		fields := CreateSatsSparkInvoiceFields(id, nil, &memo, pubKey, nil)

		addr := &pb.SparkAddress{IdentityPublicKey: pubKey, SparkInvoiceFields: fields}
		err = VerifySparkAddressSignature(addr, network)
		require.Error(t, err)
	})

	t.Run("wrong public key", func(t *testing.T) {
		// signer key
		signerKey, _ := btcec.NewPrivateKey()
		// receiver key (will not match signer)
		receiverKey, _ := btcec.NewPrivateKey()

		network := Regtest
		receiverPublicKey, err := keys.ParsePublicKey(receiverKey.PubKey().SerializeCompressed())
		require.NoError(t, err)

		uid, _ := uuid.NewV7()
		id := uid[:]
		memo := "m2"
		fields := CreateSatsSparkInvoiceFields(id, nil, &memo, receiverKey.PubKey().SerializeCompressed(), nil)
		hash, err := HashSparkInvoiceFields(fields, network, receiverPublicKey)
		require.NoError(t, err)

		sig, err := schnorr.Sign(signerKey, hash)
		require.NoError(t, err)

		addr := &pb.SparkAddress{
			IdentityPublicKey:  receiverKey.PubKey().SerializeCompressed(),
			SparkInvoiceFields: fields,
			Signature:          sig.Serialize(),
		}
		err = VerifySparkAddressSignature(addr, network)
		require.Error(t, err)
	})

	t.Run("modified fields after signing", func(t *testing.T) {
		privKey, _ := btcec.NewPrivateKey()
		pubKey := privKey.PubKey().SerializeCompressed()

		network := Regtest
		receiverPublicKey, err := keys.ParsePublicKey(pubKey)
		require.NoError(t, err)

		uid, _ := uuid.NewV7()
		id := uid[:]
		memo := "original"
		fields := CreateSatsSparkInvoiceFields(id, nil, &memo, pubKey, nil)
		hash, err := HashSparkInvoiceFields(fields, network, receiverPublicKey)
		require.NoError(t, err)

		sig, err := schnorr.Sign(privKey, hash)
		require.NoError(t, err)

		// mutate memo
		memo2 := "tampered"
		fields.Memo = &memo2

		addr := &pb.SparkAddress{
			IdentityPublicKey:  pubKey,
			SparkInvoiceFields: fields,
			Signature:          sig.Serialize(),
		}
		err = VerifySparkAddressSignature(addr, network)
		require.Error(t, err)
	})

	t.Run("invalid public key bytes", func(t *testing.T) {
		uid, _ := uuid.NewV7()
		id := uid[:]
		memo := "x"
		randKey := make([]byte, 33)
		_, _ = rand.Read(randKey)

		receiverPriv, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		receiverPubCompressed := receiverPriv.PubKey().SerializeCompressed()
		network := Regtest
		receiverPublicKey, err := keys.ParsePublicKey(receiverPubCompressed)
		require.NoError(t, err)

		fields := CreateSatsSparkInvoiceFields(id, nil, &memo, randKey, nil)
		hash, err := HashSparkInvoiceFields(fields, network, receiverPublicKey)
		require.NoError(t, err)

		// Sign with a real key but set identity key to random bytes
		privKey, _ := btcec.NewPrivateKey()
		sig, err := schnorr.Sign(privKey, hash)
		require.NoError(t, err)

		addr := &pb.SparkAddress{
			IdentityPublicKey:  randKey,
			SparkInvoiceFields: fields,
			Signature:          sig.Serialize(),
		}
		err = VerifySparkAddressSignature(addr, network)
		require.Error(t, err)
	})
}

func TestHashSparkInvoiceFieldsProducesKnownHash(t *testing.T) {
	identityPKHex := "026c943bfef71040371ca1c1d1ee1d5b203573dc97fdf6497a0b74e5aec0220e21"
	tokenIdHex := "49046dd67bbe5fc8e3abb45bc4f809b9cb5cb5871a19292fa5c7120389641363"
	senderPKHex := "02b0e3203121de9df0bd7c2b3846100e25c63310392e05961d8042fa81906d6f2b"
	idStr := "0198b4ec-3d20-7e4b-b288-1107ecf64d49"
	expiryStr := "2025-08-16T22:12:17.791Z"

	identityPK, _ := hex.DecodeString(identityPKHex)
	tokenId, _ := hex.DecodeString(tokenIdHex)
	senderPK, _ := hex.DecodeString(senderPKHex)

	uid := uuid.MustParse(idStr)
	id := uid[:]
	amount := big.NewInt(1000).Bytes()
	memo := "memo"
	expiry, err := time.Parse(time.RFC3339Nano, expiryStr)
	require.NoError(t, err)

	sparkInvoiceFields := CreateTokenSparkInvoiceFields(id, tokenId, amount, &memo, senderPK, &expiry)

	network := Regtest
	receiverPublicKey, err := keys.ParsePublicKey(identityPK)
	require.NoError(t, err)

	hash, err := HashSparkInvoiceFields(sparkInvoiceFields, network, receiverPublicKey)
	require.NoError(t, err)
	require.Len(t, hash, 32)
	require.Equal(t, "21f91b971cccc74f76fcac5384ba99d8629baff87d602f9614f6c032a2e6fb2d", hex.EncodeToString(hash))
}
