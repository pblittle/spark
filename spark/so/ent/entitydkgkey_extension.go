package ent

import (
	"context"
	"fmt"
)

// GetEntityDkgKeyPublicKey fetches the entity DKG key and returns its associated public key.
// Returns an error if no entity DKG key is found, if there are multiple entity DKG keys,
// or if the SigningKeyshare is not loaded.
func GetEntityDkgKeyPublicKey(ctx context.Context, db *Client) ([]byte, error) {
	entityDkgKey, err := db.EntityDkgKey.Query().
		WithSigningKeyshare().
		Only(ctx)
	if err != nil {
		if IsNotFound(err) {
			return nil, fmt.Errorf("entity DKG key not found")
		}
		if IsNotSingular(err) {
			return nil, fmt.Errorf("multiple entity DKG keys found, expected exactly one")
		}
		return nil, fmt.Errorf("failed to query entity DKG key: %w", err)
	}

	signingKeyshare, err := entityDkgKey.Edges.SigningKeyshareOrErr()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing keyshare from entity DKG key: %w", err)
	}

	if len(signingKeyshare.PublicKey) == 0 {
		return nil, fmt.Errorf("entity DKG key has empty public key")
	}

	return signingKeyshare.PublicKey, nil
}
