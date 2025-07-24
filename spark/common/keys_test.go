package common

import (
	"bytes"
	"encoding/hex"
	"math/big"
	rand2 "math/rand/v2"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var rng = rand2.NewChaCha8([32]byte{1})

func TestAddPrivateKeys(t *testing.T) {
	privA, pubA := genSeededKeyPair(t)
	privB, pubB := genSeededKeyPair(t)

	sum, err := AddPrivateKeys(privA.Serialize(), privB.Serialize())
	require.NoError(t, err)
	got := secp256k1.PrivKeyFromBytes(sum)

	// (A + B) - B should be A
	reconstructed, err := SubtractPrivateKeys(sum, privB.Serialize())
	require.NoError(t, err)
	assert.Equal(t, privA.Serialize(), reconstructed)
	// (A + B)'s public key should equal (pubA + pubB)
	pubSum, err := AddPublicKeys(pubA.SerializeCompressed(), pubB.SerializeCompressed())
	require.NoError(t, err)
	assert.Equal(t, pubSum, got.PubKey().SerializeCompressed())
}

func TestAddPrivateKeys_InvalidInput_Errors(t *testing.T) {
	privA, _ := genSeededKeyPair(t)
	privB, _ := genSeededKeyPair(t)
	aBytes := privA.Serialize()
	bBytes := privB.Serialize()

	tests := []struct {
		name    string
		keyA    []byte
		keyB    []byte
		wantErr string
	}{
		{
			name:    "first key too short",
			keyA:    aBytes[:31], // 31 bytes instead of 32
			keyB:    bBytes,
			wantErr: "private keys must be 32 bytes",
		},
		{
			name:    "second key too short",
			keyA:    aBytes,
			keyB:    bBytes[:31], // 31 bytes instead of 32
			wantErr: "private keys must be 32 bytes",
		},
		{
			name:    "first key too long",
			keyA:    append(aBytes, 0), // 33 bytes instead of 32
			keyB:    bBytes,
			wantErr: "private keys must be 32 bytes",
		},
		{
			name:    "second key too long",
			keyA:    aBytes,
			keyB:    append(bBytes, 0), // 33 bytes instead of 32
			wantErr: "private keys must be 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := AddPrivateKeys(tt.keyA, tt.keyB)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestAddPublicKeysRaw(t *testing.T) {
	privA, pubA := genSeededKeyPair(t)
	privB, pubB := genSeededKeyPair(t)

	sum := AddPublicKeysRaw(pubA, pubB)

	want := AddPrivateKeysRaw(privA, privB).PubKey()
	assert.Equal(t, want, sum)
}

func TestAddPublicKeys(t *testing.T) {
	privA, pubA := genSeededKeyPair(t)
	privB, pubB := genSeededKeyPair(t)

	sum, err := AddPublicKeys(pubA.SerializeCompressed(), pubB.SerializeCompressed())
	require.NoError(t, err)

	want := AddPrivateKeysRaw(privA, privB).PubKey().SerializeCompressed()
	assert.Equal(t, want, sum)
}

func TestAddPublicKeys_InvalidKeys_Errors(t *testing.T) {
	_, pubA := genSeededKeyPair(t)
	_, pubB := genSeededKeyPair(t)
	aBytes := pubA.SerializeCompressed()
	bBytes := pubB.SerializeCompressed()

	tests := []struct {
		name    string
		keyA    []byte
		keyB    []byte
		wantErr string
	}{
		{
			name:    "first key too short",
			keyA:    aBytes[:32], // 32 bytes instead of 33
			keyB:    bBytes,
			wantErr: "pubkeys must be 33 bytes",
		},
		{
			name:    "second key too short",
			keyA:    aBytes,
			keyB:    bBytes[:32], // 32 bytes instead of 33
			wantErr: "pubkeys must be 33 bytes",
		},
		{
			name:    "invalid first key",
			keyA:    bytes.Repeat([]byte{0}, 33),
			keyB:    bBytes,
			wantErr: "invalid public key: unsupported format",
		},
		{
			name:    "invalid second key",
			keyA:    aBytes,
			keyB:    bytes.Repeat([]byte{0}, 33),
			wantErr: "invalid public key: unsupported format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := AddPublicKeys(tt.keyA, tt.keyB)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestAddPublicKeysList(t *testing.T) {
	priv1, pub1 := genSeededKeyPair(t)
	priv2, pub2 := genSeededKeyPair(t)
	priv3, pub3 := genSeededKeyPair(t)
	priv4, pub4 := genSeededKeyPair(t)
	pub1Bytes := pub1.SerializeCompressed()
	pub2Bytes := pub2.SerializeCompressed()
	pub3Bytes := pub3.SerializeCompressed()
	pub4Bytes := pub4.SerializeCompressed()

	tests := []struct {
		name string
		keys [][]byte
		want *secp256k1.PublicKey
	}{
		{
			name: "single key",
			keys: [][]byte{pub1Bytes},
			want: pub1,
		},
		{
			name: "two keys",
			keys: [][]byte{pub1Bytes, pub2Bytes},
			want: AddPrivateKeysRaw(priv1, priv2).PubKey(),
		},
		{
			name: "three keys",
			keys: [][]byte{pub1Bytes, pub2Bytes, pub3Bytes},
			want: AddPrivateKeysRaw(AddPrivateKeysRaw(priv1, priv2), priv3).PubKey(),
		},
		{
			name: "four keys",
			keys: [][]byte{pub1Bytes, pub2Bytes, pub3Bytes, pub4Bytes},
			want: AddPrivateKeysRaw(AddPrivateKeysRaw(AddPrivateKeysRaw(priv1, priv2), priv3), priv4).PubKey(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AddPublicKeysList(tt.keys)
			require.NoError(t, err)
			assert.Equal(t, tt.want.SerializeCompressed(), result)
		})
	}
}

func TestAddPublicKeysList_InvalidInput_Errors(t *testing.T) {
	_, pub1 := genSeededKeyPair(t)
	validKey := pub1.SerializeCompressed()

	tests := []struct {
		name    string
		keys    [][]byte
		wantErr string
	}{
		{
			name:    "empty list",
			keys:    [][]byte{},
			wantErr: "no keys to add",
		},
		{
			name:    "key too short",
			keys:    [][]byte{validKey, validKey, validKey[:32]},
			wantErr: "pubkeys must be 33 bytes",
		},
		{
			name:    "invalid format",
			keys:    [][]byte{validKey, bytes.Repeat([]byte{0}, 33)},
			wantErr: "invalid public key: unsupported format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := AddPublicKeysList(tt.keys)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestSumOfPrivateKeys(t *testing.T) {
	keys := make([][]byte, 10)
	for i := range keys {
		priv, _ := genSeededKeyPair(t)
		keys[i] = priv.Serialize()
	}

	sum, err := SumOfPrivateKeys(keys)
	require.NoError(t, err)
	got := secp256k1.PrivKeyFromBytes(sum.Bytes())

	want := keys[0]
	for _, key := range keys[1:] {
		want, _ = AddPrivateKeys(want, key)
	}
	assert.Equal(t, want, got.Serialize())
}

func TestSumOfPrivateKeys_InvalidLength_Errors(t *testing.T) {
	keys := [][]byte{
		bytes.Repeat([]byte{2}, 32), // 32 bytes - valid length
		bytes.Repeat([]byte{1}, 31), // 31 bytes - invalid length
	}

	_, err := SumOfPrivateKeys(keys)
	assert.ErrorContains(t, err, "private keys must be 32 bytes")
}

func TestLastKeyWithTarget(t *testing.T) {
	want, _ := genSeededKeyPair(t)

	keys := make([][]byte, 10)
	for i := range keys {
		privKey, _ := genSeededKeyPair(t)
		keys[i] = privKey.Serialize()
	}

	tweak, err := LastKeyWithTarget(want.Serialize(), keys)
	require.NoError(t, err)

	sum, err := SumOfPrivateKeys(append(keys, tweak))
	require.NoError(t, err)
	subPriv := secp256k1.PrivKeyFromBytes(sum.Bytes())
	assert.Equal(t, want, subPriv)
}

func TestLastKeyWithTarget_InvalidInput_Errors(t *testing.T) {
	validTarget, _ := genSeededKeyPair(t)
	key1, _ := genSeededKeyPair(t)
	key2, _ := genSeededKeyPair(t)
	key1Bytes, key2Bytes := key1.Serialize(), key2.Serialize()
	validTargetBytes := validTarget.Serialize()
	validKeys := [][]byte{
		key1.Serialize(),
		key2.Serialize(),
	}

	tests := []struct {
		name    string
		target  []byte
		keys    [][]byte
		wantErr string
	}{
		{
			name:    "target too short",
			target:  validTargetBytes[:31], // 31 bytes instead of 32
			keys:    validKeys,
			wantErr: "target must be 32 bytes",
		},
		{
			name:    "target too long",
			target:  append(validTargetBytes, 0), // 33 bytes instead of 32
			keys:    validKeys,
			wantErr: "target must be 32 bytes",
		},
		{
			name:    "keys with invalid length",
			target:  validTargetBytes,
			keys:    [][]byte{key1Bytes[:10], key2Bytes}, // 31 bytes instead of 32
			wantErr: "private keys must be 32 bytes",
		},
		{
			name:    "keys with nil key",
			target:  validTargetBytes,
			keys:    [][]byte{key1Bytes, nil},
			wantErr: "private keys must be 32 bytes",
		},
		{
			name:    "keys with empty key",
			target:  validTargetBytes,
			keys:    [][]byte{bytes.Repeat([]byte{1}, 32), {}},
			wantErr: "private keys must be 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LastKeyWithTarget(tt.target, tt.keys)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestApplyAdditiveTweakToPublicKey(t *testing.T) {
	privKey, pubKey := genSeededKeyPair(t)
	tweak, _ := genSeededKeyPair(t)
	newPriv, err := AddPrivateKeys(privKey.Serialize(), tweak.Serialize())
	require.NoError(t, err)

	got, err := ApplyAdditiveTweakToPublicKey(pubKey.SerializeCompressed(), tweak.Serialize())
	require.NoError(t, err)

	want := secp256k1.PrivKeyFromBytes(newPriv).PubKey().SerializeCompressed()
	assert.Equal(t, want, got)
}

func TestApplyAdditiveTweakToPublicKey_InvalidInput_Errors(t *testing.T) {
	_, pubKey := genSeededKeyPair(t)
	_, tweak := genSeededKeyPair(t)
	validPubKey := pubKey.SerializeCompressed()
	validTweak := tweak.SerializeCompressed()[:32]

	tests := []struct {
		name    string
		pubKey  []byte
		tweak   []byte
		wantErr string
	}{
		{
			name:    "public key wrong length",
			pubKey:  validPubKey[:32], // 32 bytes instead of 33
			tweak:   validTweak,
			wantErr: "pubkey must be 33 bytes",
		},
		{
			name:    "invalid public key format",
			pubKey:  bytes.Repeat([]byte{0}, 33),
			tweak:   validTweak,
			wantErr: "invalid public key: unsupported format",
		},
		{
			name:    "tweak wrong length",
			pubKey:  validPubKey,
			tweak:   validTweak[:31], // 31 bytes instead of 32
			wantErr: "tweak must be 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ApplyAdditiveTweakToPublicKey(tt.pubKey, tt.tweak)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestPublicKeyFromInts_NormalizesInputs(t *testing.T) {
	// secp256k1 prime + 1 (aka 0), not normalized
	decoded, err := hex.DecodeString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f11")
	require.NoError(t, err)

	notNormal := new(big.Int).SetBytes(decoded)
	zero := big.NewInt(0)

	assert.Equal(t, PublicKeyFromInts(zero, zero), PublicKeyFromInts(notNormal, notNormal))
}

func TestSubtractPublicKeys(t *testing.T) {
	privA, pubA := genSeededKeyPair(t)
	privB, pubB := genSeededKeyPair(t)

	diff, err := SubtractPublicKeys(pubA.SerializeCompressed(), pubB.SerializeCompressed())
	require.NoError(t, err)

	// A - B should equal the public key of (privA - privB)
	wantDiff, err := SubtractPrivateKeys(privA.Serialize(), privB.Serialize())
	require.NoError(t, err)
	wantPub := secp256k1.PrivKeyFromBytes(wantDiff).PubKey().SerializeCompressed()
	assert.Equal(t, wantPub, diff)
}

func TestSubtractPublicKeys_InvalidInput_Errors(t *testing.T) {
	_, pubA := genSeededKeyPair(t)
	_, pubB := genSeededKeyPair(t)
	aBytes := pubA.SerializeCompressed()
	bBytes := pubB.SerializeCompressed()

	tests := []struct {
		name    string
		keyA    []byte
		keyB    []byte
		wantErr string
	}{
		{
			name:    "first key too short",
			keyA:    aBytes[:32], // 32 bytes instead of 33
			keyB:    bBytes,
			wantErr: "pubkeys must be 33 bytes",
		},
		{
			name:    "second key too short",
			keyA:    aBytes,
			keyB:    bBytes[:32], // 32 bytes instead of 33
			wantErr: "pubkeys must be 33 bytes",
		},
		{
			name:    "invalid first key",
			keyA:    bytes.Repeat([]byte{0}, 33),
			keyB:    bBytes,
			wantErr: "invalid public key: unsupported format",
		},
		{
			name:    "invalid second key",
			keyA:    aBytes,
			keyB:    bytes.Repeat([]byte{0}, 33),
			wantErr: "invalid public key: unsupported format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SubtractPublicKeys(tt.keyA, tt.keyB)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestSubtractPrivateKeys(t *testing.T) {
	privA, pubA := genSeededKeyPair(t)
	privB, pubB := genSeededKeyPair(t)

	diff, err := SubtractPrivateKeys(privA.Serialize(), privB.Serialize())
	require.NoError(t, err)
	got := secp256k1.PrivKeyFromBytes(diff)

	// (A - B) + B should be A
	reconstructed := AddPrivateKeysRaw(got, privB)
	assert.Equal(t, privA, reconstructed)
	// Verify the corresponding public key subtraction matches
	pubDiff, err := SubtractPublicKeys(pubA.SerializeCompressed(), pubB.SerializeCompressed())
	require.NoError(t, err)
	assert.Equal(t, pubDiff, got.PubKey().SerializeCompressed())
}

func TestSubtractPrivateKeys_InvalidInput_Errors(t *testing.T) {
	privA, _ := genSeededKeyPair(t)
	privB, _ := genSeededKeyPair(t)
	aBytes := privA.Serialize()
	bBytes := privB.Serialize()

	tests := []struct {
		name    string
		keyA    []byte
		keyB    []byte
		wantErr string
	}{
		{
			name:    "first key too short",
			keyA:    aBytes[:31], // 31 bytes instead of 32
			keyB:    bBytes,
			wantErr: "private keys must be 32 bytes",
		},
		{
			name:    "second key too short",
			keyA:    aBytes,
			keyB:    bBytes[:31], // 31 bytes instead of 32
			wantErr: "private keys must be 32 bytes",
		},
		{
			name:    "first key too long",
			keyA:    append(aBytes, 0), // 33 bytes instead of 32
			keyB:    bBytes,
			wantErr: "private keys must be 32 bytes",
		},
		{
			name:    "second key too long",
			keyA:    aBytes,
			keyB:    append(bBytes, 0), // 33 bytes instead of 32
			wantErr: "private keys must be 32 bytes",
		},
		{
			name:    "key nil",
			keyA:    nil,
			keyB:    bBytes,
			wantErr: "private keys must be 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SubtractPrivateKeys(tt.keyA, tt.keyB)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestPrivateKeyFromBytes(t *testing.T) {
	privKey, _ := genSeededKeyPair(t)
	validBytes := privKey.Serialize()

	result, err := PrivateKeyFromBytes(validBytes)

	require.NoError(t, err)
	assert.Equal(t, validBytes, result.Serialize())
}

func TestPrivateKeyFromBytes_InvalidInput_Errors(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{
			name:    "nil",
			input:   nil,
			wantErr: "private key must be 32 bytes",
		},
		{
			name:    "empty",
			input:   []byte{},
			wantErr: "private key must be 32 bytes",
		},
		{
			name:    "too short",
			input:   bytes.Repeat([]byte{1}, 31),
			wantErr: "private key must be 32 bytes",
		},
		{
			name:    "too long",
			input:   bytes.Repeat([]byte{1}, 33),
			wantErr: "private key must be 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PrivateKeyFromBytes(tt.input)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestPrivateKeyFromBigInt(t *testing.T) {
	privKey, _ := genSeededKeyPair(t)
	validBytes := privKey.Serialize()
	asInt := new(big.Int).SetBytes(validBytes)

	result, err := PrivateKeyFromBigInt(asInt)

	require.NoError(t, err)
	assert.Equal(t, validBytes, result.Serialize())
}

func TestPrivateKeyFromBigInt_InvalidInput_Errors(t *testing.T) {
	tooBig := new(big.Int).Lsh(big.NewInt(1), 256) // 2^256

	_, err := PrivateKeyFromBigInt(tooBig)

	assert.ErrorContains(t, err, "private key cannot be represented by an Int larger than 32 bytes")
}

func genSeededKeyPair(t *testing.T) (*secp256k1.PrivateKey, *secp256k1.PublicKey) {
	priv, err := secp256k1.GeneratePrivateKeyFromRand(rng)
	if err != nil {
		t.Fatal(err)
	}
	return priv, priv.PubKey()
}
