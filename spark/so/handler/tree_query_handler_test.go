package handler

import (
	"context"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
)

func TestQueryStaticDepositAddresses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, dbCtx := db.NewTestSQLiteContext(t, ctx)
	defer dbCtx.Close()

	tx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)

	// Create test data
	randomPrivKey1, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	randomPrivKey2, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	randomPrivKey3, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	signingKeyshare1, err := tx.SigningKeyshare.Create().
		SetStatus(st.KeyshareStatusAvailable).
		SetSecretShare([]byte("test_secret_share")).
		SetPublicShares(map[string][]byte{"test": []byte("test_public_share")}).
		SetPublicKey(randomPrivKey1.PubKey().SerializeCompressed()).
		SetMinSigners(2).
		SetCoordinatorIndex(0).
		Save(ctx)
	require.NoError(t, err)
	signingKeyshare2, err := tx.SigningKeyshare.Create().
		SetStatus(st.KeyshareStatusAvailable).
		SetSecretShare([]byte("test_secret_share")).
		SetPublicShares(map[string][]byte{"test": []byte("test_public_share")}).
		SetPublicKey(randomPrivKey2.PubKey().SerializeCompressed()).
		SetMinSigners(2).
		SetCoordinatorIndex(0).
		Save(ctx)
	require.NoError(t, err)
	signingKeyshare3, err := tx.SigningKeyshare.Create().
		SetStatus(st.KeyshareStatusAvailable).
		SetSecretShare([]byte("test_secret_share")).
		SetPublicShares(map[string][]byte{"test": []byte("test_public_share")}).
		SetPublicKey(randomPrivKey3.PubKey().SerializeCompressed()).
		SetMinSigners(2).
		SetCoordinatorIndex(0).
		Save(ctx)
	require.NoError(t, err)
	_, err = tx.DepositAddress.Create().
		SetAddress("bcrt1qfpk6cxxfr49wtvzxd72ahe2xtu7gj6vx7m0ksy").
		SetOwnerIdentityPubkey([]byte("test_identity_pubkey")).
		SetOwnerSigningPubkey(randomPrivKey1.PubKey().SerializeCompressed()).
		SetSigningKeyshare(signingKeyshare1).
		SetIsStatic(true).
		Save(ctx)
	require.NoError(t, err)
	_, err = tx.DepositAddress.Create().
		SetAddress("bcrt1q043w4fkg4w0jl6fxrx0kd4ww3rsq2tm4mtmv9e").
		SetOwnerIdentityPubkey([]byte("test_identity_pubkey")).
		SetOwnerSigningPubkey(randomPrivKey2.PubKey().SerializeCompressed()).
		SetSigningKeyshare(signingKeyshare2).
		SetIsStatic(true).
		Save(ctx)
	require.NoError(t, err)
	// This is a different identity pubkey, so it should not be returned
	_, err = tx.DepositAddress.Create().
		SetAddress("bcrt1q043w4fkg4w0jl6fxrx0kd4ww3rsq2tm4mtmv9d").
		SetOwnerIdentityPubkey([]byte("test_identity_pubkey2")).
		SetOwnerSigningPubkey(randomPrivKey2.PubKey().SerializeCompressed()).
		SetSigningKeyshare(signingKeyshare3).
		SetIsStatic(true).
		Save(ctx)
	require.NoError(t, err)

	t.Run("can query specific static deposit address", func(t *testing.T) {
		config := &so.Config{
			BitcoindConfigs: map[string]so.BitcoindConfig{
				"regtest": {
					DepositConfirmationThreshold: 1,
				},
			},
		}

		depositAddress := "bcrt1qfpk6cxxfr49wtvzxd72ahe2xtu7gj6vx7m0ksy"
		queryHandler := NewTreeQueryHandler(config)
		queryResult, err := queryHandler.QueryStaticDepositAddresses(ctx, &pb.QueryStaticDepositAddressesRequest{
			IdentityPublicKey: []byte("test_identity_pubkey"),
			DepositAddress:    &depositAddress,
			Network:           pb.Network_REGTEST,
		})
		require.NoError(t, err)
		require.Len(t, queryResult.DepositAddresses, 1)
		require.Equal(t, depositAddress, queryResult.DepositAddresses[0].DepositAddress)
	})

	t.Run("can query all static deposit addresses", func(t *testing.T) {
		config := &so.Config{
			BitcoindConfigs: map[string]so.BitcoindConfig{
				"regtest": {
					DepositConfirmationThreshold: 1,
				},
			},
		}

		queryHandler := NewTreeQueryHandler(config)
		queryResult, err := queryHandler.QueryStaticDepositAddresses(ctx, &pb.QueryStaticDepositAddressesRequest{
			IdentityPublicKey: []byte("test_identity_pubkey"),
			Network:           pb.Network_REGTEST,
		})
		require.NoError(t, err)
		require.Len(t, queryResult.DepositAddresses, 2)
	})
}
