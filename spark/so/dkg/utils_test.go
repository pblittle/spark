package dkg

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/so"
)

var (
	fr       = &fakeRand{}
	priv1, _ = secp256k1.GeneratePrivateKeyFromRand(fr)
	priv2, _ = secp256k1.GeneratePrivateKeyFromRand(fr)
	priv3, _ = secp256k1.GeneratePrivateKeyFromRand(fr)
)

func TestSignAndVerifyMessage(t *testing.T) {
	messageHash := sha256.Sum256([]byte("hello world"))
	priv, _ := secp256k1.GeneratePrivateKey()
	signatureBytes := signHash(priv.Serialize(), messageHash[:])

	sig, _ := ecdsa.ParseDERSignature(signatureBytes)

	assert.True(t, sig.Verify(messageHash[:], priv.PubKey()), "signature verification failed")
}

func TestRound1PackageHash(t *testing.T) {
	tests := []struct {
		name     string
		packages []map[string][]byte
		want     []byte
	}{
		{
			name:     "single package with one key",
			packages: []map[string][]byte{{"key1": priv1.Serialize()}},
			want:     mustDecodeHex(t, "e3a748ed03cb5335db1380b13f036a5e8912e1cd64cab123818c369ca784db10"),
		},
		{
			name: "single package with multiple keys",
			packages: []map[string][]byte{
				{"key1": priv1.Serialize(), "key2": priv2.Serialize(), "key3": priv3.Serialize()},
			},
			want: mustDecodeHex(t, "73088876fadb9e96dd4fa98667a56c6865fa0c13dd4c9c7eb2dc179f6fabb9f2"),
		},
		{
			name: "multiple packages",
			packages: []map[string][]byte{
				{"key1": priv1.Serialize(), "key2": priv2.Serialize()},
				{"key3": priv3.Serialize()},
			},
			want: mustDecodeHex(t, "b9d0efa1233c25aefd26d6d56d868126a32a8a71ab5b9a563dc8e165f7fcc874"),
		},
		{
			name:     "empty packages",
			packages: []map[string][]byte{},
			want:     mustDecodeHex(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := round1PackageHash(tt.packages)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRound1PackageHashPackageOrderSensitivity(t *testing.T) {
	tests := []struct {
		name     string
		packages []map[string][]byte
	}{
		{
			name: "two packages",
			packages: []map[string][]byte{
				{"key1": priv1.Serialize(), "key2": priv2.Serialize()},
				{"key3": priv3.Serialize()},
			},
		},
		{
			name: "three packages",
			packages: []map[string][]byte{
				{"key1": priv1.Serialize()},
				{"key2": priv2.Serialize()},
				{"key3": priv3.Serialize()},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := round1PackageHash(tt.packages)

			reversedPackages := append([]map[string][]byte{}, tt.packages...)
			slices.Reverse(reversedPackages)

			reversed := round1PackageHash(reversedPackages)
			assert.NotEqual(t, hash, reversed, "round1PackageHash() should be sensitive to package order")
		})
	}
}

func TestSignHash(t *testing.T) {
	hash := sha256.Sum256([]byte("test message"))

	signature := signHash(priv1.Serialize(), hash[:])
	sig, err := ecdsa.ParseDERSignature(signature)

	require.NoError(t, err)
	assert.True(t, sig.Verify(hash[:], priv1.PubKey()), "signHash() produced invalid signature")
}

func TestSignRound1Packages(t *testing.T) {
	packages := []map[string][]byte{
		{"key1": []byte("value1"), "key2": []byte("value2")},
		{"key3": []byte("value3")},
	}

	signature := signRound1Packages(priv1.Serialize(), packages)
	hash := round1PackageHash(packages)
	sig, err := ecdsa.ParseDERSignature(signature)

	require.NoError(t, err)
	assert.True(t, sig.Verify(hash, priv1.PubKey()), "signRound1Packages() produced invalid signature")
}

func TestValidateRound1Signature(t *testing.T) {
	operator1 := &so.SigningOperator{IdentityPublicKey: priv1.PubKey().SerializeCompressed()}
	operator2 := &so.SigningOperator{IdentityPublicKey: priv2.PubKey().SerializeCompressed()}
	operatorMap := map[string]*so.SigningOperator{"op1": operator1, "op2": operator2}
	packages := []map[string][]byte{
		{"key1": []byte("value1")},
		{"key2": []byte("value2")},
	}
	sig1 := signRound1Packages(priv1.Serialize(), packages)
	sig2 := signRound1Packages(priv2.Serialize(), packages)
	signatures := map[string][]byte{"op1": sig1, "op2": sig2}

	valid, failures := validateRound1Signature(packages, signatures, operatorMap)

	assert.True(t, valid)
	assert.Empty(t, failures)
}

func TestValidateRound1Signature_InvalidSignature(t *testing.T) {
	operator1 := &so.SigningOperator{IdentityPublicKey: priv1.PubKey().SerializeCompressed()}
	operator2 := &so.SigningOperator{IdentityPublicKey: priv2.PubKey().SerializeCompressed()}
	operatorMap := map[string]*so.SigningOperator{"op1": operator1, "op2": operator2}
	packages := []map[string][]byte{
		{"key1": []byte("value1")},
		{"key2": []byte("value2")},
	}
	sig2 := signRound1Packages(priv2.Serialize(), packages)
	invalidSignatures := map[string][]byte{"op1": []byte("invalid"), "op2": sig2}

	valid, failures := validateRound1Signature(packages, invalidSignatures, operatorMap)

	assert.False(t, valid, "expected false for invalid signature")
	assert.Equal(t, []string{"op1"}, failures)
}

func TestRound2PackageHash(t *testing.T) {
	tests := []struct {
		name     string
		packages [][]byte
		want     []byte
	}{
		{
			name:     "single package",
			packages: [][]byte{[]byte("package1")},
			want:     mustDecodeHex(t, "73893d30923f338108486f1a6388bac31603db30e1b954a1ab6a77b1ab9d148d"),
		},
		{
			name:     "empty packages",
			packages: [][]byte{},
			want:     mustDecodeHex(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		},
		{
			name:     "multiple packages",
			packages: [][]byte{[]byte("package1"), []byte("package2"), []byte("package3")},
			want:     mustDecodeHex(t, "48d8d70b79712c52dfa87860293ee867b61c9127e17c270a2da867975b82d527"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := round2PackageHash(tt.packages)
			assert.Equal(t, tt.want, hash)

			// Test package order sensitivity
			if len(tt.packages) > 1 {
				reversedPackages := append([][]byte{}, tt.packages...)
				slices.Reverse(reversedPackages)
				reversedHash := round2PackageHash(reversedPackages)
				assert.NotEqual(t, hash, reversedHash, "round2PackageHash() should be sensitive to package order")
			}
		})
	}
}

func TestSignRound2Packages(t *testing.T) {
	packages := [][]byte{[]byte("package1"), []byte("package2")}
	signature := signRound2Packages(priv1.Serialize(), packages)

	hash := round2PackageHash(packages)
	sig, err := ecdsa.ParseDERSignature(signature)

	require.NoError(t, err)
	assert.True(t, sig.Verify(hash, priv1.PubKey()), "signRound2Packages() produced invalid signature")
}

func TestDeriveKeyIndex(t *testing.T) {
	baseID := uuid.Must(uuid.NewRandomFromReader(fr))
	tests := []struct {
		name  string
		index uint16
	}{
		{name: "index 0", index: 0},
		{name: "index 1", index: 1},
		{name: "index 65535", index: 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			derived := deriveKeyIndex(baseID, tt.index)
			assert.Equal(t, baseID[:14], derived[:14], "deriveKeyIndex() modified first 14 bytes")

			// Verify the last 2 bytes contain the index
			derivedIndex := binary.BigEndian.Uint16(derived[14:])
			assert.Equal(t, tt.index, derivedIndex)
		})
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	decoded, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

type fakeRand struct {
	timesUsed int
}

func (f fakeRand) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = byte(f.timesUsed + i)
	}
	f.timesUsed++
	return len(p), nil
}
