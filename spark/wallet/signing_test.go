package wallet

import (
	"bytes"
	rand2 "math/rand/v2"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pbcommon "github.com/lightsparkdev/spark/proto/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so/objects"
)

var rng = rand2.NewChaCha8([32]byte{1})

func createValidPrivKey(t *testing.T) *secp256k1.PrivateKey {
	privKey, err := secp256k1.GeneratePrivateKeyFromRand(rng)
	require.NoError(t, err)
	return privKey
}

func TestCreateUserKeyPackage(t *testing.T) {
	privkey1, err := secp256k1.GeneratePrivateKeyFromRand(rng)
	require.NoError(t, err)
	privkey2, err := secp256k1.GeneratePrivateKeyFromRand(rng)
	require.NoError(t, err)

	tests := []struct {
		name               string
		signingPrivateKey  []byte
		expectedIdentifier string
		expectedMinSigners uint32
	}{
		{
			name:               "valid 32-byte private key",
			signingPrivateKey:  privkey1.Serialize(),
			expectedIdentifier: "0000000000000000000000000000000000000000000000000000000000000063",
			expectedMinSigners: 1,
		},
		{
			name:               "different valid private key",
			signingPrivateKey:  privkey2.Serialize(),
			expectedIdentifier: "0000000000000000000000000000000000000000000000000000000000000063",
			expectedMinSigners: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CreateUserKeyPackage(tt.signingPrivateKey)

			require.NotNil(t, result)
			assert.Equal(t, tt.expectedIdentifier, result.Identifier)
			assert.Equal(t, tt.signingPrivateKey, result.SecretShare)
			assert.Equal(t, tt.expectedMinSigners, result.MinSigners)

			// Verify public key is correctly derived
			privKey := secp256k1.PrivKeyFromBytes(tt.signingPrivateKey)
			expectedPubKey := privKey.PubKey().SerializeCompressed()
			assert.Equal(t, expectedPubKey, result.PublicKey)

			// Verify public shares map contains the identifier
			assert.Contains(t, result.PublicShares, tt.expectedIdentifier)
			assert.Equal(t, expectedPubKey, result.PublicShares[tt.expectedIdentifier])
		})
	}
}

func TestCreateUserKeyPackage_InvalidPrivateKey(t *testing.T) {
	tests := []struct {
		name              string
		signingPrivateKey []byte
		expectValidResult bool
	}{
		{
			name:              "nil private key",
			signingPrivateKey: nil,
			expectValidResult: false,
		},
		{
			name:              "empty private key",
			signingPrivateKey: []byte{},
			expectValidResult: false,
		},
		{
			name:              "short private key",
			signingPrivateKey: make([]byte, 16),
			expectValidResult: false,
		},
		{
			name:              "long private key",
			signingPrivateKey: make([]byte, 64),
			expectValidResult: false,
		},
		{
			name:              "zero private key (invalid on secp256k1)",
			signingPrivateKey: make([]byte, 32),
			expectValidResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CreateUserKeyPackage(tt.signingPrivateKey)
			assert.NotNil(t, result)

			assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000063", result.Identifier)
			assert.Equal(t, uint32(1), result.MinSigners)
		})
	}
}

func TestPrepareFrostSigningJobsForUserSignedRefund(t *testing.T) {
	createValidTx := func() []byte {
		tx := wire.NewMsgTx(wire.TxVersion)
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: [32]byte{1, 2, 3}, Index: 0},
			Sequence:         wire.MaxTxInSequenceNum - 1,
		})
		tx.AddTxOut(&wire.TxOut{
			Value:    100000,
			PkScript: []byte{0x76, 0xa9, 0x14}, // P2PKH prefix
		})

		var buf bytes.Buffer
		err := tx.Serialize(&buf)
		require.NoError(t, err)
		return buf.Bytes()
	}

	createReceiverPubKey := func() *secp256k1.PublicKey {
		return createValidPrivKey(t).PubKey()
	}

	tests := []struct {
		name                     string
		leaves                   []LeafKeyTweak
		signingCommitments       []*pb.RequestedSigningCommitments
		receiverIdentityPubkey   *secp256k1.PublicKey
		expectError              bool
		expectedErrorContains    string
		expectedJobsCount        int
		expectedRefundTxsCount   int
		expectedCommitmentsCount int
	}{
		{
			name: "valid single leaf",
			leaves: []LeafKeyTweak{
				{
					Leaf: &pb.TreeNode{
						Id:                 "leaf-1",
						NodeTx:             createValidTx(),
						RefundTx:           createValidTx(),
						VerifyingPublicKey: createValidPrivKey(t).PubKey().SerializeCompressed(),
					},
					SigningPrivKey: createValidPrivKey(t).Serialize(),
				},
			},
			signingCommitments: []*pb.RequestedSigningCommitments{
				{
					SigningNonceCommitments: map[string]*pbcommon.SigningCommitment{
						"test-key": {
							Hiding:  make([]byte, 33),
							Binding: make([]byte, 33),
						},
					},
				},
			},
			receiverIdentityPubkey:   createReceiverPubKey(),
			expectError:              false,
			expectedJobsCount:        1,
			expectedRefundTxsCount:   1,
			expectedCommitmentsCount: 1,
		},
		{
			name: "valid multiple leaves",
			leaves: []LeafKeyTweak{
				{
					Leaf: &pb.TreeNode{
						Id:                 "leaf-1",
						NodeTx:             createValidTx(),
						RefundTx:           createValidTx(),
						VerifyingPublicKey: createValidPrivKey(t).PubKey().SerializeCompressed(),
					},
					SigningPrivKey: createValidPrivKey(t).Serialize(),
				},
				{
					Leaf: &pb.TreeNode{
						Id:                 "leaf-2",
						NodeTx:             createValidTx(),
						RefundTx:           createValidTx(),
						VerifyingPublicKey: createValidPrivKey(t).PubKey().SerializeCompressed(),
					},
					SigningPrivKey: createValidPrivKey(t).Serialize(),
				},
			},
			signingCommitments: []*pb.RequestedSigningCommitments{
				{
					SigningNonceCommitments: map[string]*pbcommon.SigningCommitment{
						"test-key": {
							Hiding:  make([]byte, 33),
							Binding: make([]byte, 33),
						},
					},
				},
				{
					SigningNonceCommitments: map[string]*pbcommon.SigningCommitment{
						"test-key": {
							Hiding:  make([]byte, 33),
							Binding: make([]byte, 33),
						},
					},
				},
			},
			receiverIdentityPubkey:   createReceiverPubKey(),
			expectError:              false,
			expectedJobsCount:        2,
			expectedRefundTxsCount:   2,
			expectedCommitmentsCount: 2,
		},
		{
			name:                     "empty leaves",
			leaves:                   []LeafKeyTweak{},
			signingCommitments:       []*pb.RequestedSigningCommitments{},
			receiverIdentityPubkey:   createReceiverPubKey(),
			expectError:              false,
			expectedJobsCount:        0,
			expectedRefundTxsCount:   0,
			expectedCommitmentsCount: 0,
		},
		{
			name: "invalid node transaction",
			leaves: []LeafKeyTweak{
				{
					Leaf: &pb.TreeNode{
						Id:                 "leaf-1",
						NodeTx:             []byte{0x01, 0x02}, // invalid tx
						RefundTx:           createValidTx(),
						VerifyingPublicKey: createValidPrivKey(t).PubKey().SerializeCompressed(),
					},
					SigningPrivKey: createValidPrivKey(t).Serialize(),
				},
			},
			signingCommitments: []*pb.RequestedSigningCommitments{
				{
					SigningNonceCommitments: map[string]*pbcommon.SigningCommitment{
						"test-key": {
							Hiding:  make([]byte, 33),
							Binding: make([]byte, 33),
						},
					},
				},
			},
			receiverIdentityPubkey: createReceiverPubKey(),
			expectError:            true,
			expectedErrorContains:  "failed to parse node tx",
		},
		{
			name: "invalid refund transaction",
			leaves: []LeafKeyTweak{
				{
					Leaf: &pb.TreeNode{
						Id:                 "leaf-1",
						NodeTx:             createValidTx(),
						RefundTx:           []byte{0x01, 0x02}, // invalid tx
						VerifyingPublicKey: createValidPrivKey(t).PubKey().SerializeCompressed(),
					},
					SigningPrivKey: createValidPrivKey(t).Serialize(),
				},
			},
			signingCommitments: []*pb.RequestedSigningCommitments{
				{
					SigningNonceCommitments: map[string]*pbcommon.SigningCommitment{
						"test-key": {
							Hiding:  make([]byte, 33),
							Binding: make([]byte, 33),
						},
					},
				},
			},
			receiverIdentityPubkey: createReceiverPubKey(),
			expectError:            true,
			expectedErrorContains:  "failed to parse refund tx",
		},
		{
			name: "mismatched commitments length",
			leaves: []LeafKeyTweak{
				{
					Leaf: &pb.TreeNode{
						Id:                 "leaf-1",
						NodeTx:             createValidTx(),
						RefundTx:           createValidTx(),
						VerifyingPublicKey: createValidPrivKey(t).PubKey().SerializeCompressed(),
					},
					SigningPrivKey: createValidPrivKey(t).Serialize(),
				},
				{
					Leaf: &pb.TreeNode{
						Id:                 "leaf-2",
						NodeTx:             createValidTx(),
						RefundTx:           createValidTx(),
						VerifyingPublicKey: createValidPrivKey(t).PubKey().SerializeCompressed(),
					},
					SigningPrivKey: createValidPrivKey(t).Serialize(),
				},
			},
			signingCommitments: []*pb.RequestedSigningCommitments{
				{
					SigningNonceCommitments: map[string]*pbcommon.SigningCommitment{
						"test-key": {
							Hiding:  make([]byte, 33),
							Binding: make([]byte, 33),
						},
					},
				},
			},
			receiverIdentityPubkey: createReceiverPubKey(),
			expectError:            true,
			expectedErrorContains:  "mismatched lengths",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signingJobs, refundTxs, userCommitments, err := prepareFrostSigningJobsForUserSignedRefund(
				tt.leaves,
				tt.signingCommitments,
				tt.receiverIdentityPubkey,
			)

			if tt.expectError {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.expectedErrorContains)
				assert.Nil(t, signingJobs)
				assert.Nil(t, refundTxs)
				assert.Nil(t, userCommitments)
			} else {
				require.NoError(t, err)
				assert.Len(t, signingJobs, tt.expectedJobsCount)
				assert.Len(t, refundTxs, tt.expectedRefundTxsCount)
				assert.Len(t, userCommitments, tt.expectedCommitmentsCount)

				for i, job := range signingJobs {
					assert.Equal(t, tt.leaves[i].Leaf.Id, job.JobId)
					assert.NotNil(t, job.Message) // sighash should be generated
					assert.NotNil(t, job.KeyPackage)
					assert.Equal(t, tt.leaves[i].Leaf.VerifyingPublicKey, job.VerifyingKey)
					assert.NotNil(t, job.Nonce)
					assert.Equal(t, tt.signingCommitments[i].SigningNonceCommitments, job.Commitments)
					assert.NotNil(t, job.UserCommitments)

					assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000063", job.KeyPackage.Identifier)
					assert.Equal(t, tt.leaves[i].SigningPrivKey, job.KeyPackage.SecretShare)
					assert.Equal(t, uint32(1), job.KeyPackage.MinSigners)
				}

				for _, refundTx := range refundTxs {
					assert.NotEmpty(t, refundTx)
					tx := wire.NewMsgTx(wire.TxVersion)
					err := tx.Deserialize(bytes.NewReader(refundTx))
					assert.NoError(t, err)
				}

				for _, commitment := range userCommitments {
					assert.NotNil(t, commitment)
				}
			}
		})
	}
}

func TestPrepareLeafSigningJobs(t *testing.T) {
	createTestCommitment := func() *objects.SigningCommitment {
		nonce, err := objects.RandomSigningNonce()
		require.NoError(t, err)
		return nonce.SigningCommitment()
	}

	tests := []struct {
		name                  string
		leaves                []LeafKeyTweak
		refundTxs             [][]byte
		signingResults        map[string]*pbcommon.SigningResult
		userCommitments       []*objects.SigningCommitment
		signingCommitments    []*pb.RequestedSigningCommitments
		expectError           bool
		expectedErrorContains string
		expectedJobsCount     int
	}{
		{
			name: "valid single leaf signing job",
			leaves: []LeafKeyTweak{
				{
					Leaf: &pb.TreeNode{
						Id: "leaf-1",
					},
					SigningPrivKey: createValidPrivKey(t).Serialize(),
				},
			},
			refundTxs: [][]byte{
				{0x01, 0x02, 0x03},
			},
			signingResults: map[string]*pbcommon.SigningResult{
				"leaf-1": {
					SignatureShare: []byte{0x11, 0x22, 0x33},
				},
			},
			userCommitments: []*objects.SigningCommitment{
				createTestCommitment(),
			},
			signingCommitments: []*pb.RequestedSigningCommitments{
				{
					SigningNonceCommitments: map[string]*pbcommon.SigningCommitment{
						"test-key": {
							Hiding:  make([]byte, 33),
							Binding: make([]byte, 33),
						},
					},
				},
			},
			expectError:       false,
			expectedJobsCount: 1,
		},
		{
			name: "valid multiple leaf signing jobs",
			leaves: []LeafKeyTweak{
				{
					Leaf: &pb.TreeNode{
						Id: "leaf-1",
					},
					SigningPrivKey: createValidPrivKey(t).Serialize(),
				},
				{
					Leaf: &pb.TreeNode{
						Id: "leaf-2",
					},
					SigningPrivKey: createValidPrivKey(t).Serialize(),
				},
			},
			refundTxs: [][]byte{
				{0x01, 0x02, 0x03},
				{0x04, 0x05, 0x06},
			},
			signingResults: map[string]*pbcommon.SigningResult{
				"leaf-1": {
					SignatureShare: []byte{0x11, 0x22, 0x33},
				},
				"leaf-2": {
					SignatureShare: []byte{0x44, 0x55, 0x66},
				},
			},
			userCommitments: []*objects.SigningCommitment{
				createTestCommitment(),
				createTestCommitment(),
			},
			signingCommitments: []*pb.RequestedSigningCommitments{
				{
					SigningNonceCommitments: map[string]*pbcommon.SigningCommitment{
						"test-key": {
							Hiding:  make([]byte, 33),
							Binding: make([]byte, 33),
						},
					},
				},
				{
					SigningNonceCommitments: map[string]*pbcommon.SigningCommitment{
						"test-key": {
							Hiding:  make([]byte, 33),
							Binding: make([]byte, 33),
						},
					},
				},
			},
			expectError:       false,
			expectedJobsCount: 2,
		},
		{
			name:               "empty inputs",
			leaves:             []LeafKeyTweak{},
			refundTxs:          [][]byte{},
			signingResults:     map[string]*pbcommon.SigningResult{},
			userCommitments:    []*objects.SigningCommitment{},
			signingCommitments: []*pb.RequestedSigningCommitments{},
			expectError:        false,
			expectedJobsCount:  0,
		},
		{
			name: "missing signing result",
			leaves: []LeafKeyTweak{
				{
					Leaf: &pb.TreeNode{
						Id: "leaf-1",
					},
					SigningPrivKey: createValidPrivKey(t).Serialize(),
				},
			},
			refundTxs: [][]byte{
				{0x01, 0x02, 0x03},
			},
			signingResults: map[string]*pbcommon.SigningResult{},
			userCommitments: []*objects.SigningCommitment{
				createTestCommitment(),
			},
			signingCommitments: []*pb.RequestedSigningCommitments{
				{
					SigningNonceCommitments: map[string]*pbcommon.SigningCommitment{
						"test-key": {
							Hiding:  make([]byte, 33),
							Binding: make([]byte, 33),
						},
					},
				},
			},
			expectError:           true,
			expectedErrorContains: "mismatched lengths: leaves: 1, results: 0",
		},
		{
			name: "mismatched array lengths - fewer refund txs",
			leaves: []LeafKeyTweak{
				{
					Leaf: &pb.TreeNode{
						Id: "leaf-1",
					},
					SigningPrivKey: createValidPrivKey(t).Serialize(),
				},
				{
					Leaf: &pb.TreeNode{
						Id: "leaf-2",
					},
					SigningPrivKey: createValidPrivKey(t).Serialize(),
				},
			},
			refundTxs: [][]byte{
				{0x01, 0x02, 0x03}, // Missing second refund tx
			},
			signingResults: map[string]*pbcommon.SigningResult{
				"leaf-1": {
					SignatureShare: []byte{0x11, 0x22, 0x33},
				},
				"leaf-2": {
					SignatureShare: []byte{0x44, 0x55, 0x66},
				},
			},
			userCommitments: []*objects.SigningCommitment{
				createTestCommitment(),
				createTestCommitment(),
			},
			signingCommitments: []*pb.RequestedSigningCommitments{
				{
					SigningNonceCommitments: map[string]*pbcommon.SigningCommitment{
						"test-key": {
							Hiding:  make([]byte, 33),
							Binding: make([]byte, 33),
						},
					},
				},
				{
					SigningNonceCommitments: map[string]*pbcommon.SigningCommitment{
						"test-key": {
							Hiding:  make([]byte, 33),
							Binding: make([]byte, 33),
						},
					},
				},
			},
			expectError:           true,
			expectedErrorContains: "mismatched lengths: leaves: 2, refund txs: 1",
		},
		{
			name: "mismatched array lengths - fewer user commitments",
			leaves: []LeafKeyTweak{
				{
					Leaf: &pb.TreeNode{
						Id: "leaf-1",
					},
					SigningPrivKey: createValidPrivKey(t).Serialize(),
				},
				{
					Leaf: &pb.TreeNode{
						Id: "leaf-2",
					},
					SigningPrivKey: createValidPrivKey(t).Serialize(),
				},
			},
			refundTxs: [][]byte{
				{0x01, 0x02, 0x03},
				{0x04, 0x05, 0x06},
			},
			signingResults: map[string]*pbcommon.SigningResult{
				"leaf-1": {
					SignatureShare: []byte{0x11, 0x22, 0x33},
				},
				"leaf-2": {
					SignatureShare: []byte{0x44, 0x55, 0x66},
				},
			},
			userCommitments: []*objects.SigningCommitment{
				createTestCommitment(), // Missing second commitment
			},
			signingCommitments: []*pb.RequestedSigningCommitments{
				{
					SigningNonceCommitments: map[string]*pbcommon.SigningCommitment{
						"test-key": {
							Hiding:  make([]byte, 33),
							Binding: make([]byte, 33),
						},
					},
				},
				{
					SigningNonceCommitments: map[string]*pbcommon.SigningCommitment{
						"test-key": {
							Hiding:  make([]byte, 33),
							Binding: make([]byte, 33),
						},
					},
				},
			},
			expectError:           true,
			expectedErrorContains: "mismatched lengths: leaves: 2, user commitments: 1",
		},
		{
			name: "mismatched array lengths - fewer signing commitments",
			leaves: []LeafKeyTweak{
				{
					Leaf: &pb.TreeNode{
						Id: "leaf-1",
					},
					SigningPrivKey: createValidPrivKey(t).Serialize(),
				},
				{
					Leaf: &pb.TreeNode{
						Id: "leaf-2",
					},
					SigningPrivKey: createValidPrivKey(t).Serialize(),
				},
			},
			refundTxs: [][]byte{
				{0x01, 0x02, 0x03},
				{0x04, 0x05, 0x06},
			},
			signingResults: map[string]*pbcommon.SigningResult{
				"leaf-1": {
					SignatureShare: []byte{0x11, 0x22, 0x33},
				},
				"leaf-2": {
					SignatureShare: []byte{0x44, 0x55, 0x66},
				},
			},
			userCommitments: []*objects.SigningCommitment{
				createTestCommitment(),
				createTestCommitment(),
			},
			signingCommitments: []*pb.RequestedSigningCommitments{
				{
					SigningNonceCommitments: map[string]*pbcommon.SigningCommitment{
						"test-key": {
							Hiding:  make([]byte, 33),
							Binding: make([]byte, 33),
						},
					},
				},
				// Missing second signing commitment
			},
			expectError:           true,
			expectedErrorContains: "mismatched lengths: leaves: 2, commitments: 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leafSigningJobs, err := prepareLeafSigningJobs(
				tt.leaves,
				tt.refundTxs,
				tt.signingResults,
				tt.userCommitments,
				tt.signingCommitments,
			)

			if tt.expectError {
				require.ErrorContains(t, err, tt.expectedErrorContains)
			} else {
				require.NoError(t, err)
				assert.Len(t, leafSigningJobs, tt.expectedJobsCount)

				for i, job := range leafSigningJobs {
					assert.Equal(t, tt.leaves[i].Leaf.Id, job.LeafId)
					assert.Equal(t, tt.refundTxs[i], job.RawTx)
					assert.NotNil(t, job.SigningPublicKey)
					assert.NotNil(t, job.SigningNonceCommitment)
					assert.Equal(t, tt.signingResults[tt.leaves[i].Leaf.Id].SignatureShare, job.UserSignature)
					assert.NotNil(t, job.SigningCommitments)
					assert.Equal(t, tt.signingCommitments[i].SigningNonceCommitments, job.SigningCommitments.SigningCommitments)

					// Verify public key is correctly derived from private key
					privKey := secp256k1.PrivKeyFromBytes(tt.leaves[i].SigningPrivKey)
					expectedPubKey := privKey.PubKey().SerializeCompressed()
					// Note that the following line acts as a regression test for putting
					// the signing private key in the signing public key field.
					// See https://linear.app/lightsparkdev/issue/LIG-8042
					assert.Equal(t, expectedPubKey, job.SigningPublicKey)
				}
			}
		})
	}
}
