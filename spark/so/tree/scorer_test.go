package tree

import (
	"context"
	"math/rand/v2"
	"testing"

	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/proto/spark_tree"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

var seeded = rand.NewChaCha8([32]byte{0})

func TestPolarityScorer_Score(t *testing.T) {
	sspKey := []byte("ssp_key")
	userKey := []byte("user_key")
	leafID := seededUUID()

	tests := []struct {
		name        string
		setupScores map[uuid.UUID]map[string]float32
		want        float32
	}{
		{
			name: "leaf exists with both scores",
			setupScores: map[uuid.UUID]map[string]float32{
				leafID: {
					string(sspKey):  0.8,
					string(userKey): 0.3,
				},
			},
			want: 0.5,
		},
		{
			name: "leaf exists with only ssp score",
			setupScores: map[uuid.UUID]map[string]float32{
				leafID: {string(sspKey): 0.8},
			},
			want: 0.8,
		},
		{
			name: "leaf exists with only user score",
			setupScores: map[uuid.UUID]map[string]float32{
				leafID: {string(userKey): 0.3},
			},
			want: -0.3,
		},
		{
			name: "leaf exists with neither score",
			setupScores: map[uuid.UUID]map[string]float32{
				leafID: {"other_key": 0.5},
			},
			want: 0.0,
		},
		{
			name:        "leaf does not exist",
			setupScores: map[uuid.UUID]map[string]float32{},
			want:        0.0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			_, dbCtx := db.NewTestSQLiteContext(t, ctx)
			defer dbCtx.Close()

			scorer := NewPolarityScorer(dbCtx.Client)
			scorer.probPubKeyCanClaim = tc.setupScores

			score := scorer.Score(leafID, sspKey, userKey)
			assert.InEpsilon(t, tc.want, score, 0.01)
		})
	}
}

func TestPolarityScorer_UpdateLeaves(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, dbCtx := db.NewTestSQLiteContext(t, ctx)
	defer dbCtx.Close()

	dbTx, err := ent.GetDbFromContext(ctx)
	if err != nil {
		t.Fatalf("failed to get or create current tx: %v", err)
	}

	scorer := NewPolarityScorer(dbTx.Client())

	tree := dbTx.Tree.Create().
		SetOwnerIdentityPubkey([]byte("tree_owner")).
		SetStatus(st.TreeStatusAvailable).
		SetNetwork(st.NetworkMainnet).
		SetBaseTxid([]byte("base_txid")).
		SetVout(0).
		SaveX(ctx)

	keyshare := dbTx.SigningKeyshare.Create().
		SetStatus(st.KeyshareStatusAvailable).
		SetSecretShare([]byte("secret")).
		SetPublicShares(map[string][]uint8{}).
		SetPublicKey([]byte("public_key")).
		SetMinSigners(2).
		SetCoordinatorIndex(1).
		SaveX(ctx)

	parentOwner := []byte("parent_owner")
	parentNode := dbTx.TreeNode.Create().
		SetTree(tree).
		SetStatus(st.TreeNodeStatusAvailable).
		SetOwnerIdentityPubkey(parentOwner).
		SetOwnerSigningPubkey(parentOwner).
		SetValue(1000).
		SetVerifyingPubkey([]byte("verifying_key")).
		SetSigningKeyshare(keyshare).
		SetRawTx([]byte("raw_tx")).
		SetVout(0).
		SaveX(ctx)

	// Create child nodes
	child1 := dbTx.TreeNode.Create().
		SetTree(tree).
		SetStatus(st.TreeNodeStatusAvailable).
		SetOwnerIdentityPubkey([]byte("owner1")).
		SetOwnerSigningPubkey([]byte("owner1")).
		SetValue(500).
		SetVerifyingPubkey([]byte("verifying_key1")).
		SetSigningKeyshare(keyshare).
		SetRawTx([]byte("raw_tx1")).
		SetVout(0).
		SetParent(parentNode).
		SaveX(ctx)

	child2 := dbTx.TreeNode.Create().
		SetTree(tree).
		SetStatus(st.TreeNodeStatusAvailable).
		SetOwnerIdentityPubkey([]byte("owner2")).
		SetOwnerSigningPubkey([]byte("owner2")).
		SetValue(500).
		SetVerifyingPubkey([]byte("verifying_key2")).
		SetSigningKeyshare(keyshare).
		SetRawTx([]byte("raw_tx2")).
		SetVout(1).
		SetParent(parentNode).
		SaveX(ctx)

	scorer.UpdateLeaves(ctx, parentNode)

	assert.Len(t, scorer.probPubKeyCanClaim, 2)
	for _, leaf := range []*ent.TreeNode{child1, child2} {
		scores, exists := scorer.probPubKeyCanClaim[leaf.ID]
		assert.True(t, exists, "Leaf %s should have scores", leaf.ID)
		assert.NotEmpty(t, scores, "Leaf %s should have non-empty scores", leaf.ID)
	}
}

func TestPolarityScorer_FetchPolarityScores(t *testing.T) {
	tests := []struct {
		name           string
		request        *spark_tree.FetchPolarityScoreRequest
		setupScores    map[uuid.UUID]map[string]float32
		expectedCount  int
		expectedScores map[string]float32 // key: leafID_pubkey
	}{
		{
			name: "fetch all scores",
			request: &spark_tree.FetchPolarityScoreRequest{
				PublicKeys: [][]byte{},
			},
			setupScores: map[uuid.UUID]map[string]float32{
				seededUUID(): {
					"pubkey1": 0.5,
					"pubkey2": 0.3,
				},
				seededUUID(): {
					"pubkey3": 0.7,
				},
			},
			expectedCount: 3,
		},
		{
			name: "fetch specific pubkeys",
			request: &spark_tree.FetchPolarityScoreRequest{
				PublicKeys: [][]byte{
					[]byte("pubkey1"),
					[]byte("pubkey3"),
				},
			},
			setupScores: map[uuid.UUID]map[string]float32{
				seededUUID(): {
					"pubkey1": 0.5,
					"pubkey2": 0.3,
				},
				seededUUID(): {
					"pubkey3": 0.7,
				},
			},
			expectedCount: 2,
		},
		{
			name: "no matching pubkeys",
			request: &spark_tree.FetchPolarityScoreRequest{
				PublicKeys: [][]byte{[]byte("nonexistent")},
			},
			setupScores: map[uuid.UUID]map[string]float32{
				seededUUID(): {"pubkey1": 0.5},
			},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			_, dbCtx := db.NewTestSQLiteContext(t, ctx)
			defer dbCtx.Close()

			scorer := NewPolarityScorer(dbCtx.Client)
			scorer.probPubKeyCanClaim = tt.setupScores

			mockStream := &mockSparkTreeServiceFetchPolarityScoresServer{
				ctx:    ctx,
				scores: []*spark_tree.PolarityScore{},
			}

			err := scorer.FetchPolarityScores(tt.request, mockStream)
			require.NoError(t, err)

			for _, score := range mockStream.scores {
				assert.NotEmpty(t, score.LeafId)
				assert.NotEmpty(t, score.PublicKey)
				assert.NotZero(t, score.Score)
			}
		})
	}
}

// Mock implementation for testing FetchPolarityScores
type mockSparkTreeServiceFetchPolarityScoresServer struct {
	grpc.ServerStream
	ctx    context.Context
	scores []*spark_tree.PolarityScore
}

func (m *mockSparkTreeServiceFetchPolarityScoresServer) Context() context.Context {
	return m.ctx
}

func (m *mockSparkTreeServiceFetchPolarityScoresServer) Send(score *spark_tree.PolarityScore) error {
	m.scores = append(m.scores, score)
	return nil
}

func seededUUID() uuid.UUID {
	return uuid.Must(uuid.NewRandomFromReader(seeded))
}
