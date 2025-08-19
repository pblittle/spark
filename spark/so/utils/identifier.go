package utils

import "encoding/hex"

// IndexToIdentifier converts a uint32 index to a 32-byte identifier string.
// The index is incremented by 1 before conversion to ensure the identifier is not 0.
func IndexToIdentifier(index uint32) string {
	as64Bit := uint64(index) + 1
	identifierBytes := make([]byte, 32)
	for i := 0; i < 8; i++ {
		identifierBytes[31-i] = byte(as64Bit >> (i * 8))
	}
	return hex.EncodeToString(identifierBytes)
}
