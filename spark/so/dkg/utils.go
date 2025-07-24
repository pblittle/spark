package dkg

import (
	"crypto/sha256"
	"encoding/binary"
	"maps"
	"slices"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/so"
)

func round1PackageHash(packageMaps []map[string][]byte) []byte {
	// For each map, create a deterministic string representation
	finalHasher := sha256.New()
	for _, m := range packageMaps {
		keys := slices.Sorted(maps.Keys(m)) // Only sort keys within each map

		// Create a hash for this map
		hasher := sha256.New()
		for _, k := range keys {
			hasher.Write([]byte(k))
			hasher.Write(m[k])
		}
		// Calculate final hash preserving array order
		finalHasher.Write(hasher.Sum(nil))
	}

	return finalHasher.Sum(nil)
}

func signHash(privateKey []byte, hash []byte) []byte {
	priv := secp256k1.PrivKeyFromBytes(privateKey)
	return ecdsa.Sign(priv, hash).Serialize()
}

func signRound1Packages(privateKey []byte, round1Packages []map[string][]byte) []byte {
	hash := round1PackageHash(round1Packages)
	return signHash(privateKey, hash)
}

func validateRound1Signature(round1Packages []map[string][]byte, round1Signatures map[string][]byte, operatorMap map[string]*so.SigningOperator) (bool, []string) {
	hash := round1PackageHash(round1Packages)

	var validationFailures []string
	for identifier, operator := range operatorMap {
		signature, ok := round1Signatures[identifier]
		if !ok {
			validationFailures = append(validationFailures, identifier)
			continue
		}

		pub, err := secp256k1.ParsePubKey(operator.IdentityPublicKey)
		if err != nil {
			validationFailures = append(validationFailures, identifier)
			continue
		}

		sig, err := ecdsa.ParseDERSignature(signature)
		if err != nil {
			validationFailures = append(validationFailures, identifier)
			continue
		}

		if !sig.Verify(hash, pub) {
			validationFailures = append(validationFailures, identifier)
		}
	}

	return len(validationFailures) == 0, validationFailures
}

func round2PackageHash(round2Packages [][]byte) []byte {
	hasher := sha256.New()
	for _, p := range round2Packages {
		hasher.Write(p)
	}
	return hasher.Sum(nil)
}

func signRound2Packages(privateKey []byte, round2Packages [][]byte) []byte {
	hash := round2PackageHash(round2Packages)
	return signHash(privateKey, hash)
}

func deriveKeyIndex(batchID uuid.UUID, index uint16) uuid.UUID {
	derivedID := batchID
	// Write the index to the last 2 bytes
	binary.BigEndian.PutUint16(derivedID[14:], index)
	return derivedID
}
