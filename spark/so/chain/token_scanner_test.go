package chain

import (
	"context"
	"encoding/binary"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/btcsuite/btcd/txscript"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	testutil "github.com/lightsparkdev/spark/test_util"
	"github.com/stretchr/testify/assert"
)

var (
	seededRand   = rand.NewChaCha8([32]byte{})
	maxSupply    = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	issuerPubKey = genSeededPubKey()
)

func TestParseTokenAnnouncement(t *testing.T) {
	tests := []struct {
		name   string
		script []byte
		want   *common.TokenMetadata
	}{
		{name: "empty script", script: []byte{}, want: nil},
		{name: "nil", script: nil, want: nil},
		{name: "not OP_RETURN", script: []byte{txscript.OP_DUP, txscript.OP_HASH160}, want: nil},
		{name: "OP_RETURN but too short", script: []byte{txscript.OP_RETURN}, want: nil},
		{name: "not announcement", script: directPush([]byte("NOTOK")), want: nil},
		{name: "OP_RETURN with invalid kind", script: directPush(append([]byte(announcementPrefix), 9, 9)), want: nil},
		{
			name:   "valid token announcement",
			script: directPush(createValidTokenData()),
			want:   createExpectedTokenMetadata(),
		},
		{
			name: "valid UTF-8 with unicode characters",
			script: func() []byte {
				nameBytes := []byte("🚀BTC")
				tickerBytes := []byte("🚀")
				return pushData1(slices.Concat(
					[]byte(announcementPrefix),
					creationAnnouncementKind[:],
					issuerPubKey,
					[]byte{byte(len(nameBytes))},
					nameBytes,
					[]byte{byte(len(tickerBytes))},
					tickerBytes,
					[]byte{8},
					maxSupply,
					[]byte{0},
				))
			}(),
			want: &common.TokenMetadata{
				IssuerPublicKey:         issuerPubKey,
				TokenName:               "🚀BTC",
				TokenTicker:             "🚀",
				Decimals:                8,
				MaxSupply:               maxSupply,
				IsFreezable:             false,
				CreationEntityPublicKey: common.L1CreationEntityPublicKey,
				Network:                 common.Testnet,
			},
		},
		{
			name: "invalid push operation",
			script: []byte{
				txscript.OP_RETURN,
				0xff, // Invalid push operation
			},
			want: nil,
		},
		{
			name:   "valid direct push (OP_1 to OP_75)",
			script: directPush(createValidTokenData()),
			want:   createExpectedTokenMetadata(),
		},
		{
			name:   "valid OP_PUSHDATA1",
			script: pushData1(createValidTokenData()),
			want:   createExpectedTokenMetadata(),
		},
		{
			name:   "valid OP_PUSHDATA2",
			script: pushData2(createValidTokenData()),
			want:   createExpectedTokenMetadata(),
		},
		{
			name:   "valid OP_PUSHDATA4",
			script: pushData4(createValidTokenData()),
			want:   createExpectedTokenMetadata(),
		},
		{
			name:   "incomplete OP_PUSHDATA1",
			script: []byte{txscript.OP_RETURN, txscript.OP_PUSHDATA1}, // OP_PUSHDATA1 without length byte
			want:   nil,
		},
		{
			name:   "incomplete OP_PUSHDATA2",
			script: []byte{txscript.OP_RETURN, txscript.OP_PUSHDATA2, 0x01}, // Only one byte of length
			want:   nil,
		},
		{
			name:   "incomplete OP_PUSHDATA4",
			script: []byte{txscript.OP_RETURN, txscript.OP_PUSHDATA4, 0x01, 0x02, 0x03}, // Only one byte of length
			want:   nil,
		},
		{
			name: "insufficient data after length",
			script: []byte{
				txscript.OP_RETURN,
				txscript.OP_PUSHDATA1,
				10,      // Claim 10 bytes follow
				1, 2, 3, // Only provide 3
			},
			want: nil,
		},
		{
			name:   "extra data after push",
			script: append(directPush(createValidTokenData()), 0), // Extra unwanted byte
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseTokenAnnouncement(tt.script, common.Testnet)
			require.NoError(t, err)

			if tt.want == nil {
				require.Nil(t, result)
				return
			}
			require.NotNil(t, result)

			got, err := result.ToTokenMetadata()
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseTokenAnnouncement_Errors(t *testing.T) {
	tests := []struct {
		name    string
		script  []byte
		wantErr string
	}{
		{
			name: "extra data after push",
			script: pushData1(slices.Concat(
				[]byte(announcementPrefix),
				creationAnnouncementKind[:],
				issuerPubKey,
				[]byte{4}, []byte("ABCD"),
				[]byte{4}, []byte("TICK"),
				[]byte{8},
				maxSupply,
				[]byte{1},
				[]byte{1}, // An extra, invalid byte
			)),
			wantErr: "unexpected data after token announcement",
		},
		{
			name: "name too short",
			script: directPush(slices.Concat(
				[]byte(announcementPrefix),
				creationAnnouncementKind[:],
				issuerPubKey,
				[]byte{2}, []byte("AB"), // Too short
				[]byte{4}, []byte("TICK"),
				[]byte{8},
				maxSupply,
				[]byte{1},
			)),
			wantErr: "invalid length: expected between 3 and 20, got 2",
		},
		{
			name: "name too long",
			script: pushData1(slices.Concat(
				[]byte(announcementPrefix),
				creationAnnouncementKind[:],
				issuerPubKey,
				[]byte{25}, []byte("1234567890123456789012345"), // Too long
				[]byte{4}, []byte("TICK"),
				[]byte{8},
				maxSupply,
				[]byte{1},
			)),
			wantErr: "invalid length: expected between 3 and 20, got 25",
		},
		{
			name: "ticker too short",
			script: directPush(slices.Concat(
				[]byte(announcementPrefix),
				creationAnnouncementKind[:],
				issuerPubKey,
				[]byte{9}, []byte("TestToken"),
				[]byte{2}, []byte("XY"), // Too short
				[]byte{8},
				maxSupply,
				[]byte{1},
			)),
			wantErr: "invalid length: expected between 3 and 6, got 2",
		},
		{
			name: "ticker too long",
			script: pushData1(slices.Concat(
				[]byte(announcementPrefix),
				creationAnnouncementKind[:],
				issuerPubKey,
				[]byte{9}, []byte("TestToken"),
				[]byte{7}, []byte("1234567"), // Too long
				[]byte{8},
				maxSupply,
				[]byte{1},
			)),
			wantErr: "invalid length: expected between 3 and 6, got 7",
		},
		{
			name: "invalid max supply length",
			script: pushData1(slices.Concat(
				[]byte(announcementPrefix),
				creationAnnouncementKind[:],
				issuerPubKey,
				[]byte{9}, []byte("TestToken"),
				[]byte{4}, []byte("TICK"),
				[]byte{8},
				maxSupply[:15], // 15 bytes for max supply
			)),
			wantErr: "invalid max supply: insufficient data",
		},
		{
			name: "missing is_freezable",
			script: directPush(slices.Concat(
				[]byte(announcementPrefix),
				creationAnnouncementKind[:],
				issuerPubKey,
				[]byte{9}, []byte("TestToken"),
				[]byte{4}, []byte("TICK"),
				[]byte{8},
				maxSupply,
			)),
			wantErr: "invalid is_freezable: insufficient data",
		},
		{
			name: "invalid UTF-8 in name",
			script: directPush(slices.Concat(
				[]byte(announcementPrefix),
				creationAnnouncementKind[:],
				issuerPubKey,
				[]byte{3}, []byte{0xFF, 0x80, 0x80}, // Invalid UTF-8
				[]byte{4}, []byte("TICK"),
				[]byte{8},
				maxSupply,
				[]byte{1},
			)),
			wantErr: "invalid name: invalid UTF-8",
		},
		{
			name: "invalid UTF-8 in ticker",
			script: directPush(slices.Concat(
				[]byte(announcementPrefix),
				creationAnnouncementKind[:],
				issuerPubKey,
				[]byte{9}, []byte("TestToken"),
				[]byte{4}, []byte{0xC0, 0x80, 0xFF, 0x80}, // Invalid UTF-8
				[]byte{8},
				maxSupply,
				[]byte{1},
			)),
			wantErr: "invalid ticker: invalid UTF-8",
		},
		{
			name: "valid non-normalized UFT-8 in name",
			script: directPush(slices.Concat(
				[]byte(announcementPrefix),
				creationAnnouncementKind[:],
				issuerPubKey,
				[]byte{3}, []byte("e\u0301"), // Non-normalized name
				[]byte{4}, []byte("TICK"),
				[]byte{8},
				maxSupply,
				[]byte{1},
			)),
			wantErr: "invalid name: not NFC-normalized",
		},
		{
			name: "valid non-normalized UTF-8 in ticker",
			script: directPush(slices.Concat(
				[]byte(announcementPrefix),
				creationAnnouncementKind[:],
				issuerPubKey,
				[]byte{9}, []byte("TestToken"),
				[]byte{3}, []byte("e\u0301"), // Non-normalized ticker
				[]byte{8},
				maxSupply,
				[]byte{1},
			)),
			wantErr: "invalid ticker: not NFC-normalized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseTokenAnnouncement(tt.script, common.Testnet)
			require.ErrorContains(t, err, tt.wantErr)
			assert.Nil(t, result)
		})
	}
}

func directPush(data []byte) []byte {
	script := append([]byte{txscript.OP_RETURN}, byte(len(data))) // Direct push (length between 1-75)
	return append(script, data...)
}

func pushData1(data []byte) []byte {
	script := []byte{
		txscript.OP_RETURN,
		txscript.OP_PUSHDATA1,
		byte(len(data)), // Length byte for OP_PUSHDATA1
	}
	return append(script, data...)
}

func pushData2(data []byte) []byte {
	script := []byte{txscript.OP_RETURN, txscript.OP_PUSHDATA2}
	script = binary.LittleEndian.AppendUint16(script, uint16(len(data)))
	return append(script, data...)
}

func pushData4(data []byte) []byte {
	script := []byte{txscript.OP_RETURN, txscript.OP_PUSHDATA4}
	script = binary.LittleEndian.AppendUint32(script, uint32(len(data)))
	return append(script, data...)
}

func createValidTokenData() []byte {
	return slices.Concat(
		[]byte(announcementPrefix),
		creationAnnouncementKind[:],
		issuerPubKey,
		[]byte{9}, []byte("TestToken"),
		[]byte{4}, []byte("TICK"),
		[]byte{8},
		maxSupply,
		[]byte{1},
	)
}

func createExpectedTokenMetadata() *common.TokenMetadata {
	return &common.TokenMetadata{
		IssuerPublicKey:         issuerPubKey,
		TokenName:               "TestToken",
		TokenTicker:             "TICK",
		Decimals:                8,
		MaxSupply:               maxSupply,
		IsFreezable:             true,
		CreationEntityPublicKey: common.L1CreationEntityPublicKey,
		Network:                 common.Testnet,
	}
}

func genSeededPubKey() []byte {
	key, err := secp256k1.GeneratePrivateKeyFromRand(seededRand)
	if err != nil {
		panic(err)
	}
	return key.PubKey().SerializeCompressed()
}

func TestCreateTokenEntities_L1TokenDuplicateConstraints(t *testing.T) {
	ctx, dbCtx := db.NewTestSQLiteContext(t, context.Background())
	defer dbCtx.Close()

	config, err := testutil.TestConfig()
	require.NoError(t, err)

	// Disable Spark token creation to simplify the test setup
	config.Token.DisableSparkTokenCreationForL1TokenAnnouncements = true

	// Get database transaction from context
	dbTx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)

	// Create test data
	issuerPubKey := genSeededPubKey()
	testTxHash := chainhash.Hash{0x01, 0x02, 0x03}

	// Create L1TokenCreate entity that implements TokenMetadataProvider
	l1TokenToCreate := &ent.L1TokenCreate{
		IssuerPublicKey: issuerPubKey,
		TokenName:       "TestToken",
		TokenTicker:     "TST",
		Decimals:        8,
		MaxSupply:       []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		IsFreezable:     false,
		Network:         common.SchemaNetwork(common.Testnet),
	}

	// Test 1: First call should succeed and create L1TokenCreate entity
	err = createTokenEntities(ctx, config, dbTx, l1TokenToCreate, testTxHash)
	require.NoError(t, err, "First call to createTokenEntities should succeed")

	// Verify L1TokenCreate entity was created
	l1TokenCount, err := dbTx.L1TokenCreate.Query().Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, l1TokenCount, "Should have exactly one L1TokenCreate entity")

	// Test 2: Second call with same issuer public key should not error and not create duplicate
	err = createTokenEntities(ctx, config, dbTx, l1TokenToCreate, testTxHash)
	require.NoError(t, err, "Second call to createTokenEntities should not error due to duplicate")

	// Verify no duplicate L1TokenCreate entity was created
	l1TokenCountAfter, err := dbTx.L1TokenCreate.Query().Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, l1TokenCountAfter, "Should still have exactly one L1TokenCreate entity")
}

func TestCreateTokenEntities_SparkTokenDuplicateConstraints(t *testing.T) {
	ctx, dbCtx := db.NewTestSQLiteContext(t, context.Background())
	defer dbCtx.Close()

	config, err := testutil.TestConfig()
	require.NoError(t, err)

	// Enable Spark token creation for this test
	config.Token.DisableSparkTokenCreationForL1TokenAnnouncements = false

	// Get database transaction from context
	dbTx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)

	// Create required EntityDkgKey for Spark token creation
	entityDkgPublicKey := genSeededPubKey() // Generate proper 33-byte public key
	signingKeyshare, err := dbTx.SigningKeyshare.Create().
		SetStatus(st.KeyshareStatusAvailable).
		SetSecretShare([]byte("test_secret")).
		SetPublicShares(map[string][]byte{}).
		SetPublicKey(entityDkgPublicKey).
		SetMinSigners(1).
		SetCoordinatorIndex(0).
		Save(ctx)
	require.NoError(t, err)

	_, err = dbTx.EntityDkgKey.Create().
		SetSigningKeyshare(signingKeyshare).
		Save(ctx)
	require.NoError(t, err)

	// Create test data
	issuerPubKey := genSeededPubKey()
	testTxHash := chainhash.Hash{0x01, 0x02, 0x03}

	// Create L1TokenCreate entity that implements TokenMetadataProvider
	l1TokenToCreate := &ent.L1TokenCreate{
		IssuerPublicKey: issuerPubKey,
		TokenName:       "TestToken",
		TokenTicker:     "TST",
		Decimals:        8,
		MaxSupply:       make([]byte, 16),
		IsFreezable:     false,
		Network:         common.SchemaNetwork(common.Testnet),
	}

	// Test 1: First call should succeed and create both L1TokenCreate and TokenCreate entities
	err = createTokenEntities(ctx, config, dbTx, l1TokenToCreate, testTxHash)
	require.NoError(t, err, "First call to createTokenEntities should succeed")

	// Verify both entities were created
	l1TokenCount, err := dbTx.L1TokenCreate.Query().Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, l1TokenCount, "Should have exactly one L1TokenCreate entity")

	sparkTokenCount, err := dbTx.TokenCreate.Query().Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, sparkTokenCount, "Should have exactly one TokenCreate entity")

	// Test 2: Second call with same issuer public key should not error and not create duplicates
	err = createTokenEntities(ctx, config, dbTx, l1TokenToCreate, testTxHash)
	require.NoError(t, err, "Second call to createTokenEntities should not error due to duplicates")

	// Verify no duplicate entities were created
	l1TokenCountAfter, err := dbTx.L1TokenCreate.Query().Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, l1TokenCountAfter, "Should still have exactly one L1TokenCreate entity")

	sparkTokenCountAfter, err := dbTx.TokenCreate.Query().Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, sparkTokenCountAfter, "Should still have exactly one TokenCreate entity")
}
