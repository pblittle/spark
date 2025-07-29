package task

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/lightsparkdev/spark/so/db"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	testutil "github.com/lightsparkdev/spark/test_util"
)

func TestBackfillTokenOutputTokenIdentifiersAndTokenCreateEdges(t *testing.T) {
	randomBytes := func(n int) []byte {
		b := make([]byte, n)
		_, err := rand.Read(b)
		require.NoError(t, err)
		return b
	}

	ctx, dbCtx := db.NewTestSQLiteContext(t, context.Background())
	defer dbCtx.Close()

	signingKeyshare, err := dbCtx.Client.SigningKeyshare.Create().
		SetStatus(st.KeyshareStatusAvailable).
		SetSecretShare(randomBytes(32)).
		SetPublicShares(map[string][]byte{}).
		SetPublicKey(randomBytes(33)).
		SetMinSigners(1).
		SetCoordinatorIndex(0).
		Save(ctx)
	require.NoError(t, err)

	issuerPubKey := randomBytes(33)
	tokenIdentifier := randomBytes(32)

	tokenCreate, err := dbCtx.Client.TokenCreate.Create().
		SetIssuerPublicKey(issuerPubKey).
		SetTokenName("TestToken").
		SetTokenTicker("TST").
		SetDecimals(0).
		SetMaxSupply(randomBytes(16)).
		SetIsFreezable(false).
		SetNetwork(st.NetworkRegtest).
		SetCreationEntityPublicKey(randomBytes(33)).
		SetTokenIdentifier(tokenIdentifier).
		Save(ctx)
	require.NoError(t, err)

	// Create a token output that is missing the TokenIdentifier and TokenCreate
	tokenOutput, err := dbCtx.Client.TokenOutput.Create().
		SetStatus(st.TokenOutputStatusCreatedFinalized).
		SetOwnerPublicKey(randomBytes(33)).
		SetWithdrawBondSats(1000).
		SetWithdrawRelativeBlockLocktime(10).
		SetWithdrawRevocationCommitment(randomBytes(33)).
		SetTokenPublicKey(issuerPubKey).
		SetTokenAmount(randomBytes(16)).
		SetCreatedTransactionOutputVout(0).
		SetRevocationKeyshareID(signingKeyshare.ID).
		SetNetwork(st.NetworkRegtest).
		Save(ctx)
	require.NoError(t, err)

	// Generate a new random public key - that has no matching token_create
	var legacyTokenOutputPubkey []byte
	for {
		candidateBytes := randomBytes(33)
		if bytes.Equal(candidateBytes, issuerPubKey) {
			continue
		}
		legacyTokenOutputPubkey = candidateBytes
		break
	}

	// Create a legacy token output from prior to april 28th
	legacyTokenOutput, err := dbCtx.Client.TokenOutput.Create().
		SetStatus(st.TokenOutputStatusCreatedFinalized).
		SetCreateTime(time.Date(2025, time.April, 27, 0, 0, 0, 0, time.UTC)). // Create time prior to april 28th
		SetTokenPublicKey(legacyTokenOutputPubkey).                           // New random public key - no matching token_create
		SetOwnerPublicKey(randomBytes(33)).
		SetWithdrawBondSats(1000).
		SetWithdrawRelativeBlockLocktime(10).
		SetWithdrawRevocationCommitment(randomBytes(33)).
		SetTokenAmount(randomBytes(16)).
		SetCreatedTransactionOutputVout(0).
		SetRevocationKeyshareID(signingKeyshare.ID).
		SetNetwork(st.NetworkRegtest).
		Save(ctx)
	require.NoError(t, err)

	if tx := dbCtx.Session.GetTxIfExists(); tx != nil {
		require.NoError(t, tx.Commit())
	}

	// Verify the initial state of the token output
	initialOutput, err := dbCtx.Client.TokenOutput.Get(ctx, tokenOutput.ID)
	require.NoError(t, err)
	require.Nil(t, initialOutput.TokenIdentifier)
	require.Equal(t, uuid.Nil, initialOutput.TokenCreateID)

	var backfillTask StartupTask
	for _, stsk := range AllStartupTasks() {
		if stsk.Name == "backfill_token_output_token_identifiers_and_token_create_edges" {
			backfillTask = stsk
			break
		}
	}
	require.NotNil(t, backfillTask.Task, "backfill task not found")

	cfg, err := testutil.TestConfig()
	require.NoError(t, err)

	// Run with the flag disabled
	cfg.Token.EnableBackfillTokenOutputTask = false
	require.NoError(t, backfillTask.RunOnce(cfg, dbCtx.Client))

	backfillDisabledOutput, err := dbCtx.Client.TokenOutput.Get(ctx, tokenOutput.ID)
	require.NoError(t, err)
	require.Nil(t, backfillDisabledOutput.TokenIdentifier)
	require.Equal(t, uuid.Nil, backfillDisabledOutput.TokenCreateID)

	// Run with the flag enabled
	cfg.Token.EnableBackfillTokenOutputTask = true
	require.NoError(t, backfillTask.RunOnce(cfg, dbCtx.Client))

	updatedOutput, err := dbCtx.Client.TokenOutput.Get(ctx, tokenOutput.ID)
	require.NoError(t, err)
	require.Equal(t, tokenIdentifier, updatedOutput.TokenIdentifier)
	require.Equal(t, tokenCreate.ID, updatedOutput.TokenCreateID)

	updatedLegacyOutput, err := dbCtx.Client.TokenOutput.Get(ctx, legacyTokenOutput.ID)
	require.NoError(t, err)
	require.Nil(t, updatedLegacyOutput.TokenIdentifier)
	require.Equal(t, uuid.Nil, updatedLegacyOutput.TokenCreateID)

	// If the task is run again, there should be no errors.
	require.NoError(t, backfillTask.RunOnce(cfg, dbCtx.Client))
}
