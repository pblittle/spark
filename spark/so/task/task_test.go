package task

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/lightsparkdev/spark/common/keys"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/lightsparkdev/spark/so/db"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	sparktesting "github.com/lightsparkdev/spark/testing"
)

var seededRand = rand.NewChaCha8([32]byte{})

func TestBackfillTokenOutputTokenIdentifiersAndTokenCreateEdges(t *testing.T) {
	ctx, dbCtx := db.NewTestSQLiteContext(t, t.Context())
	defer dbCtx.Close()

	signingKeyshare, err := dbCtx.Client.SigningKeyshare.Create().
		SetStatus(st.KeyshareStatusAvailable).
		SetSecretShare(randomBytes(32)).
		SetPublicShares(map[string][]byte{}).
		SetPublicKey(keys.MustGeneratePrivateKeyFromRand(seededRand).Public().Serialize()).
		SetMinSigners(1).
		SetCoordinatorIndex(0).
		Save(ctx)
	require.NoError(t, err)

	issuerPubKey := keys.MustGeneratePrivateKeyFromRand(seededRand).Public()
	tokenIdentifier := randomBytes(32)

	tokenCreate, err := dbCtx.Client.TokenCreate.Create().
		SetIssuerPublicKey(issuerPubKey.Serialize()).
		SetTokenName("TestToken").
		SetTokenTicker("TST").
		SetDecimals(0).
		SetMaxSupply(randomBytes(16)).
		SetIsFreezable(false).
		SetNetwork(st.NetworkRegtest).
		SetCreationEntityPublicKey(keys.MustGeneratePrivateKeyFromRand(seededRand).Public().Serialize()).
		SetTokenIdentifier(tokenIdentifier).
		Save(ctx)
	require.NoError(t, err)

	// Create a token output that is missing the TokenIdentifier and TokenCreate
	tokenOutput, err := dbCtx.Client.TokenOutput.Create().
		SetStatus(st.TokenOutputStatusCreatedFinalized).
		SetOwnerPublicKey(keys.MustGeneratePrivateKeyFromRand(seededRand).Public().Serialize()).
		SetWithdrawBondSats(1000).
		SetWithdrawRelativeBlockLocktime(10).
		SetWithdrawRevocationCommitment(randomBytes(33)).
		SetTokenPublicKey(issuerPubKey.Serialize()).
		SetTokenAmount(randomBytes(16)).
		SetCreatedTransactionOutputVout(0).
		SetRevocationKeyshareID(signingKeyshare.ID).
		SetNetwork(st.NetworkRegtest).
		Save(ctx)
	require.NoError(t, err)

	// Generate a new random public key - that has no matching token_create
	var legacyTokenOutputPubkey keys.Public
	for {
		if candidate := keys.MustGeneratePrivateKeyFromRand(seededRand).Public(); !candidate.Equals(issuerPubKey) {
			legacyTokenOutputPubkey = candidate
			break
		}
	}

	// Create a legacy token output from prior to april 28th
	legacyTokenOutput, err := dbCtx.Client.TokenOutput.Create().
		SetStatus(st.TokenOutputStatusCreatedFinalized).
		SetCreateTime(time.Date(2025, time.April, 27, 0, 0, 0, 0, time.UTC)). // Create time prior to april 28th
		SetTokenPublicKey(legacyTokenOutputPubkey.Serialize()).               // New random public key - no matching token_create
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

	var backfillTask StartupTaskSpec
	for _, stsk := range AllStartupTasks() {
		if stsk.Name == "backfill_token_output_token_identifiers_and_token_create_edges" {
			backfillTask = stsk
			break
		}
	}
	require.NotNil(t, backfillTask.Task, "backfill task not found")

	cfg, err := sparktesting.TestConfig()
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

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = seededRand.Read(b)
	return b
}
