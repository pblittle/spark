package tokens

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sparkpb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	sparktesting "github.com/lightsparkdev/spark/testing"
)

type queryTokenTestFixture struct {
	Handler *QueryTokenHandler
	Ctx     context.Context
	Tx      *ent.Tx
	Cleanup func()
}

func setupQueryTokenTestHandler(t *testing.T) *queryTokenTestFixture {
	t.Helper()

	config, err := sparktesting.TestConfig()
	require.NoError(t, err)

	ctx, dbContext := db.NewTestSQLiteContext(t, t.Context())

	handler := &QueryTokenHandler{
		config:                     config,
		includeExpiredTransactions: true,
	}

	cleanup := func() {
		dbContext.Close()
	}

	return &queryTokenTestFixture{
		Handler: handler,
		Ctx:     ctx,
		Cleanup: cleanup,
	}
}

func TestExpiredOutputBeforeFinalization(t *testing.T) {
	setup := setupQueryTokenTestHandler(t)
	defer setup.Cleanup()

	handler := setup.Handler
	ctx := setup.Ctx

	tx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)

	t.Run("return output after transaction has expired in signed state", func(t *testing.T) {
		randomBytes := func(length int) []byte {
			b := make([]byte, length)
			_, err := rand.Read(b)
			require.NoError(t, err)
			return b
		}

		// Create two signing keyshares (one for the mint output, one for transfer output)
		signKS1, err := tx.SigningKeyshare.Create().
			SetStatus(st.KeyshareStatusAvailable).
			SetSecretShare(randomBytes(32)).
			SetPublicShares(map[string][]byte{}).
			SetPublicKey(randomBytes(33)).
			SetMinSigners(1).
			SetCoordinatorIndex(0).
			Save(ctx)
		require.NoError(t, err)

		signKS2, err := tx.SigningKeyshare.Create().
			SetStatus(st.KeyshareStatusAvailable).
			SetSecretShare(randomBytes(32)).
			SetPublicShares(map[string][]byte{}).
			SetPublicKey(randomBytes(33)).
			SetMinSigners(1).
			SetCoordinatorIndex(0).
			Save(ctx)
		require.NoError(t, err)

		// Create a mint transaction that produces an output we will later spend
		mintEnt, err := tx.TokenMint.Create().
			SetIssuerPublicKey(randomBytes(33)).
			SetWalletProvidedTimestamp(uint64(time.Now().UnixMilli())).
			SetIssuerSignature(randomBytes(64)).
			Save(ctx)
		require.NoError(t, err)

		tokenIdentifier := randomBytes(32)
		tokenCreate, err := tx.TokenCreate.Create().
			SetIssuerPublicKey(randomBytes(33)).
			SetTokenName("TestToken").
			SetTokenTicker("TT").
			SetDecimals(0).
			SetMaxSupply(randomBytes(16)).
			SetIsFreezable(true).
			SetNetwork(st.NetworkRegtest).
			SetTokenIdentifier(tokenIdentifier).
			SetCreationEntityPublicKey(handler.config.IdentityPublicKey().Serialize()).
			Save(ctx)
		require.NoError(t, err)

		mintTx, err := tx.TokenTransaction.Create().
			SetPartialTokenTransactionHash(randomBytes(32)).
			SetFinalizedTokenTransactionHash(randomBytes(32)).
			SetStatus(st.TokenTransactionStatusFinalized).
			SetMintID(mintEnt.ID).
			Save(ctx)
		require.NoError(t, err)

		mintOutput, err := tx.TokenOutput.Create().
			SetStatus(st.TokenOutputStatusCreatedFinalized).
			SetOwnerPublicKey(randomBytes(33)).
			SetWithdrawBondSats(1_000).
			SetWithdrawRelativeBlockLocktime(10).
			SetWithdrawRevocationCommitment(randomBytes(33)).
			SetTokenAmount(randomBytes(16)).
			SetCreatedTransactionOutputVout(0).
			SetRevocationKeyshareID(signKS1.ID).
			SetTokenIdentifier(tokenIdentifier).
			SetTokenCreateID(tokenCreate.ID).
			SetOutputCreatedTokenTransactionID(mintTx.ID).
			SetNetwork(st.NetworkRegtest).
			Save(ctx)
		require.NoError(t, err)

		// Create a transfer transaction (SIGNED & expired) that spends the mint output
		expiredAt := time.Now().Add(-1 * time.Hour)
		transferTx, err := tx.TokenTransaction.Create().
			SetPartialTokenTransactionHash(randomBytes(32)).
			SetFinalizedTokenTransactionHash(randomBytes(32)).
			SetStatus(st.TokenTransactionStatusSigned).
			SetExpiryTime(expiredAt).
			Save(ctx)
		require.NoError(t, err)

		// Update mintOutput to mark it as spent by transferTx
		_, err = mintOutput.Update().
			SetStatus(st.TokenOutputStatusSpentSigned).
			SetOutputSpentTokenTransactionID(transferTx.ID).
			SetSpentTransactionInputVout(0).
			Save(ctx)
		require.NoError(t, err)

		// Create a new output produced by the transferTx
		_, err = tx.TokenOutput.Create().
			SetStatus(st.TokenOutputStatusCreatedSigned).
			SetOwnerPublicKey(randomBytes(33)).
			SetWithdrawBondSats(500).
			SetWithdrawRelativeBlockLocktime(10).
			SetWithdrawRevocationCommitment(randomBytes(33)).
			SetTokenAmount(randomBytes(16)).
			SetCreatedTransactionOutputVout(0).
			SetRevocationKeyshareID(signKS2.ID).
			SetTokenIdentifier(tokenIdentifier).
			SetTokenCreateID(tokenCreate.ID).
			SetOutputCreatedTokenTransactionID(transferTx.ID).
			SetNetwork(st.NetworkRegtest).
			Save(ctx)
		require.NoError(t, err)

		outputsResp, err := handler.QueryTokenOutputsToken(ctx, &tokenpb.QueryTokenOutputsRequest{
			OwnerPublicKeys: [][]byte{mintOutput.OwnerPublicKey},
			Network:         sparkpb.Network_REGTEST,
		})
		require.NoError(t, err)

		require.Len(t, outputsResp.OutputsWithPreviousTransactionData, 1)
		assert.Equal(t, mintOutput.ID.String(), outputsResp.OutputsWithPreviousTransactionData[0].Output.GetId())
	})
}
