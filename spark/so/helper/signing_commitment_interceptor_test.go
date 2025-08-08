package helper

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSigningCommitmentsFromContext_MapUpdate(t *testing.T) {
	// Setup initial commitments map
	initialCommitments := map[uint][]*ent.SigningCommitment{
		1: {
			{ID: uuid.New()},
			{ID: uuid.New()},
			{ID: uuid.New()},
		},
		2: {
			{ID: uuid.New()},
			{ID: uuid.New()},
		},
	}

	ctx := context.WithValue(context.Background(), signingCommitmentsKey, initialCommitments)

	// Test getting commitments and verify map is updated
	commitments, err := GetSigningCommitmentsFromContext(ctx, 2, 1)

	// Assertions
	require.NoError(t, err)
	assert.Len(t, commitments, 2)

	// Verify the map was updated (only 1 commitment should remain)
	updatedMap := ctx.Value(signingCommitmentsKey).(map[uint][]*ent.SigningCommitment)
	remainingCommitments := updatedMap[1]
	assert.Len(t, remainingCommitments, 1)

	// Verify operator 2 was not affected
	operator2Commitments := updatedMap[2]
	assert.Len(t, operator2Commitments, 2)
}

func TestGetSigningCommitmentsFromContext_NotEnoughCommitments(t *testing.T) {
	// Setup initial commitments map with insufficient commitments
	initialCommitments := map[uint][]*ent.SigningCommitment{
		1: {
			{ID: uuid.New()},
		},
	}

	ctx := context.WithValue(context.Background(), signingCommitmentsKey, initialCommitments)

	// Test getting more commitments than available
	commitments, err := GetSigningCommitmentsFromContext(ctx, 2, 1)

	// Assertions
	require.Error(t, err)
	assert.Nil(t, commitments)
	assert.Contains(t, err.Error(), "not enough signing commitments")
}

func TestGetSigningCommitmentsFromContext_OperatorNotFound(t *testing.T) {
	// Setup initial commitments map
	initialCommitments := map[uint][]*ent.SigningCommitment{
		1: {
			{ID: uuid.New()},
		},
	}

	ctx := context.WithValue(context.Background(), signingCommitmentsKey, initialCommitments)

	// Test getting commitments for operator that doesn't exist
	commitments, err := GetSigningCommitmentsFromContext(ctx, 1, 999)

	// Assertions
	require.Error(t, err)
	assert.Nil(t, commitments)
	assert.Contains(t, err.Error(), "not enough signing commitments")
}
