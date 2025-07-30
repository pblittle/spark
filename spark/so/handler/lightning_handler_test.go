package handler_test

import (
	"context"
	"testing"

	pbcommon "github.com/lightsparkdev/spark/proto/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/handler"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
)

func TestValidateDuplicateLeaves(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, dbCtx := db.NewTestSQLiteContext(t, ctx)
	defer dbCtx.Close()

	config := &so.Config{}
	lightningHandler := handler.NewLightningHandler(config)

	// Helper function to create a UserSignedTxSigningJob
	createSigningJob := func(leafID string) *pb.UserSignedTxSigningJob {
		return &pb.UserSignedTxSigningJob{
			LeafId: leafID,
			SigningCommitments: &pb.SigningCommitments{
				SigningCommitments: map[string]*pbcommon.SigningCommitment{
					"test": {
						Hiding:  []byte("test_hiding"),
						Binding: []byte("test_binding"),
					},
				},
			},
			SigningNonceCommitment: &pbcommon.SigningCommitment{
				Hiding:  []byte("test_nonce_hiding"),
				Binding: []byte("test_nonce_binding"),
			},
			UserSignature: []byte("test_signature"),
			RawTx:         []byte("test_raw_tx"),
		}
	}

	t.Run("successful validation with no duplicates", func(t *testing.T) {
		leavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf2"),
			createSigningJob("leaf3"),
		}
		directLeavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf2"),
		}
		directFromCpfpLeavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf3"),
		}

		err := lightningHandler.ValidateDuplicateLeaves(ctx, leavesToSend, directLeavesToSend, directFromCpfpLeavesToSend)
		assert.NoError(t, err)
	})

	t.Run("successful validation with empty arrays", func(t *testing.T) {
		err := lightningHandler.ValidateDuplicateLeaves(ctx, []*pb.UserSignedTxSigningJob{}, []*pb.UserSignedTxSigningJob{}, []*pb.UserSignedTxSigningJob{})
		assert.NoError(t, err)
	})

	t.Run("successful validation with only leavesToSend", func(t *testing.T) {
		leavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf2"),
		}

		err := lightningHandler.ValidateDuplicateLeaves(ctx, leavesToSend, []*pb.UserSignedTxSigningJob{}, []*pb.UserSignedTxSigningJob{})
		assert.NoError(t, err)
	})

	t.Run("duplicate in leavesToSend", func(t *testing.T) {
		leavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf1"), // Duplicate
			createSigningJob("leaf2"),
		}

		err := lightningHandler.ValidateDuplicateLeaves(ctx, leavesToSend, []*pb.UserSignedTxSigningJob{}, []*pb.UserSignedTxSigningJob{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate leaf id: leaf1")
	})

	t.Run("duplicate in directLeavesToSend", func(t *testing.T) {
		leavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf2"),
		}
		directLeavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf1"), // Duplicate
		}

		err := lightningHandler.ValidateDuplicateLeaves(ctx, leavesToSend, directLeavesToSend, []*pb.UserSignedTxSigningJob{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate leaf id: leaf1")
	})

	t.Run("duplicate in directFromCpfpLeavesToSend", func(t *testing.T) {
		leavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf2"),
		}
		directFromCpfpLeavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf1"), // Duplicate
		}

		err := lightningHandler.ValidateDuplicateLeaves(ctx, leavesToSend, []*pb.UserSignedTxSigningJob{}, directFromCpfpLeavesToSend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate leaf id: leaf1")
	})

	t.Run("leaf id not found in leavesToSend for directLeavesToSend", func(t *testing.T) {
		leavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf2"),
		}
		directLeavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf3"), // Not in leavesToSend
		}

		err := lightningHandler.ValidateDuplicateLeaves(ctx, leavesToSend, directLeavesToSend, []*pb.UserSignedTxSigningJob{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "leaf id leaf3 not found in leaves to send")
	})

	t.Run("leaf id not found in leavesToSend for directFromCpfpLeavesToSend", func(t *testing.T) {
		leavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf2"),
		}
		directFromCpfpLeavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf3"), // Not in leavesToSend
		}

		err := lightningHandler.ValidateDuplicateLeaves(ctx, leavesToSend, []*pb.UserSignedTxSigningJob{}, directFromCpfpLeavesToSend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "leaf id leaf3 not found in leaves to send")
	})

	t.Run("multiple duplicates across different arrays", func(t *testing.T) {
		leavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf1"), // Duplicate in leavesToSend
			createSigningJob("leaf2"),
		}
		directLeavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf2"),
			createSigningJob("leaf2"), // Duplicate in directLeavesToSend
		}
		directFromCpfpLeavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf1"), // Duplicate in directFromCpfpLeavesToSend
		}

		err := lightningHandler.ValidateDuplicateLeaves(ctx, leavesToSend, directLeavesToSend, directFromCpfpLeavesToSend)
		assert.Error(t, err)
		// Should detect the first duplicate it encounters (in leavesToSend)
		assert.Contains(t, err.Error(), "duplicate leaf id: leaf1")
	})

	t.Run("complex scenario with all arrays populated", func(t *testing.T) {
		leavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf2"),
			createSigningJob("leaf3"),
			createSigningJob("leaf4"),
		}
		directLeavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf2"),
			createSigningJob("leaf3"),
		}
		directFromCpfpLeavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf4"),
		}

		err := lightningHandler.ValidateDuplicateLeaves(ctx, leavesToSend, directLeavesToSend, directFromCpfpLeavesToSend)
		assert.NoError(t, err)
	})

	t.Run("nil arrays", func(t *testing.T) {
		err := lightningHandler.ValidateDuplicateLeaves(ctx, nil, nil, nil)
		assert.NoError(t, err)
	})

	t.Run("mixed nil and non-nil arrays", func(t *testing.T) {
		leavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
			createSigningJob("leaf2"),
		}

		err := lightningHandler.ValidateDuplicateLeaves(ctx, leavesToSend, nil, nil)
		assert.NoError(t, err)
	})

	t.Run("empty leavesToSend with non-empty other arrays", func(t *testing.T) {
		directLeavesToSend := []*pb.UserSignedTxSigningJob{
			createSigningJob("leaf1"),
		}

		err := lightningHandler.ValidateDuplicateLeaves(ctx, []*pb.UserSignedTxSigningJob{}, directLeavesToSend, []*pb.UserSignedTxSigningJob{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "leaf id leaf1 not found in leaves to send")
	})
}

// Note: StorePreimageShare requires complex cryptographic validation
// that's difficult to mock in unit tests. These tests focus on basic validation.
func TestStorePreimageShareEdgeCases(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, dbCtx := db.NewTestSQLiteContext(t, ctx)
	defer dbCtx.Close()

	config := &so.Config{
		Threshold: 2,
		Index:     0,
	}
	lightningHandler := handler.NewLightningHandler(config)

	t.Run("nil preimage share returns error", func(t *testing.T) {
		req := &pb.StorePreimageShareRequest{
			PaymentHash:           []byte("payment_hash"),
			PreimageShare:         nil,
			Threshold:             uint32(config.Threshold),
			InvoiceString:         "invalid_bolt11",
			UserIdentityPublicKey: []byte("user_identity_key"),
		}

		err := lightningHandler.StorePreimageShare(ctx, req)
		assert.ErrorContains(t, err, "preimage share is nil")
	})

	t.Run("empty proofs array returns error", func(t *testing.T) {
		req := &pb.StorePreimageShareRequest{
			PaymentHash:           []byte("payment_hash"),
			PreimageShare:         &pb.SecretShare{SecretShare: []byte("test"), Proofs: [][]byte{}},
			Threshold:             uint32(config.Threshold),
			InvoiceString:         "invalid_bolt11",
			UserIdentityPublicKey: []byte("user_identity_key"),
		}

		err := lightningHandler.StorePreimageShare(ctx, req)
		assert.ErrorContains(t, err, "preimage share proofs is empty")
	})
}

func TestGetSigningCommitments(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, dbCtx := db.NewTestSQLiteContext(t, ctx)
	defer dbCtx.Close()

	config := &so.Config{}
	lightningHandler := handler.NewLightningHandler(config)

	tests := []struct {
		name           string
		nodeIds        []string
		count          uint32
		expectError    bool
		expectedErrMsg string
		expectEmpty    bool
	}{
		{
			name:           "invalid node ID format",
			nodeIds:        []string{"invalid-uuid-format"},
			count:          1,
			expectError:    true,
			expectedErrMsg: "unable to parse node id",
			expectEmpty:    false,
		},
		{
			name:        "empty node IDs",
			nodeIds:     []string{},
			count:       1,
			expectError: false,
			expectEmpty: true,
		},
		{
			name:        "non-existent node ID",
			nodeIds:     []string{"12345678-1234-1234-1234-123456789012"},
			count:       1,
			expectError: false,
			expectEmpty: true,
		},
		{
			name:        "zero count defaults to 1",
			nodeIds:     []string{},
			count:       0,
			expectError: false,
			expectEmpty: true,
		},
		{
			name:           "multiple invalid node IDs",
			nodeIds:        []string{"invalid-1", "invalid-2"},
			count:          1,
			expectError:    true,
			expectedErrMsg: "unable to parse node id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &pb.GetSigningCommitmentsRequest{
				NodeIds: tt.nodeIds,
				Count:   tt.count,
			}

			resp, err := lightningHandler.GetSigningCommitments(ctx, req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.expectedErrMsg != "" {
					assert.Contains(t, err.Error(), tt.expectedErrMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				if tt.expectEmpty {
					assert.Empty(t, resp.SigningCommitments)
				}
			}
		})
	}
}

func TestValidatePreimage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, dbCtx := db.NewTestSQLiteContext(t, ctx)
	defer dbCtx.Close()

	config := &so.Config{}
	lightningHandler := handler.NewLightningHandler(config)

	tests := []struct {
		name              string
		paymentHash       []byte
		preimage          []byte
		identityPublicKey []byte
		expectError       bool
		expectedErrMsgs   []string // Multiple possible error messages
	}{
		{
			name:              "invalid preimage - hash mismatch",
			paymentHash:       []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
			preimage:          []byte("wrong_preimage_that_doesnt_match_hash"),
			identityPublicKey: []byte("identity_key"),
			expectError:       true,
			expectedErrMsgs:   []string{"invalid preimage"},
		},
		{
			name:              "non-existent preimage request",
			paymentHash:       []byte("some_hash_that_matches_preimage_"),
			preimage:          []byte("test_preimage_32_bytes_long_____"),
			identityPublicKey: []byte("identity_key"),
			expectError:       true,
			expectedErrMsgs:   []string{"invalid preimage", "unable to get preimage request"},
		},
		{
			name:              "empty payment hash",
			paymentHash:       []byte{},
			preimage:          []byte("test_preimage"),
			identityPublicKey: []byte("identity_key"),
			expectError:       true,
			expectedErrMsgs:   []string{"invalid preimage"},
		},
		{
			name:              "empty preimage",
			paymentHash:       []byte("payment_hash_32_bytes_long______"),
			preimage:          []byte{},
			identityPublicKey: []byte("identity_key"),
			expectError:       true,
			expectedErrMsgs:   []string{"invalid preimage"},
		},
		{
			name:              "nil identity public key",
			paymentHash:       []byte("payment_hash_32_bytes_long______"),
			preimage:          []byte("test_preimage_32_bytes_long_____"),
			identityPublicKey: nil,
			expectError:       true,
			expectedErrMsgs:   []string{"invalid preimage", "unable to get preimage request"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &pb.ProvidePreimageRequest{
				PaymentHash:       tt.paymentHash,
				Preimage:          tt.preimage,
				IdentityPublicKey: tt.identityPublicKey,
			}

			transfer, err := lightningHandler.ValidatePreimage(ctx, req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, transfer)

				// Check if error message contains one of the expected messages
				errorMatches := false
				for _, expectedMsg := range tt.expectedErrMsgs {
					if assert.ObjectsAreEqual(expectedMsg, err.Error()) {
						errorMatches = true
						break
					}
				}
				assert.True(t, errorMatches,
					"Expected one of %v, got: %v", tt.expectedErrMsgs, err.Error())
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, transfer)
			}
		})
	}
}

func TestReturnLightningPayment(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, dbCtx := db.NewTestSQLiteContext(t, ctx)
	defer dbCtx.Close()

	config := &so.Config{}
	lightningHandler := handler.NewLightningHandler(config)

	t.Run("non-existent payment hash", func(t *testing.T) {
		req := &pb.ReturnLightningPaymentRequest{
			PaymentHash:           []byte("non_existent_payment_hash_______"),
			UserIdentityPublicKey: []byte("user_identity_key"),
		}

		resp, err := lightningHandler.ReturnLightningPayment(ctx, req, true) // internal=true to skip auth
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "unable to get preimage request")
	})
}

// Note: validateNodeOwnership and validateHasSession are private methods,
// so we test them indirectly through GetSigningCommitments which calls validateHasSession

func TestValidateGetPreimageRequestEdgeCases(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, dbCtx := db.NewTestSQLiteContext(t, ctx)
	defer dbCtx.Close()

	config := &so.Config{
		SignerAddress: "invalid_address", // This will cause connection failures
	}
	lightningHandler := handler.NewLightningHandler(config)

	// Valid 33-byte compressed secp256k1 public key for destination
	validPubKey := []byte{0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98}

	tests := []struct {
		name                       string
		cpfpTransactions           []*pb.UserSignedTxSigningJob
		directTransactions         []*pb.UserSignedTxSigningJob
		directFromCpfpTransactions []*pb.UserSignedTxSigningJob
		destinationPubkey          []byte
		expectError                bool
		expectedErrMsg             string
	}{
		{
			name:              "nil cpfp transactions",
			cpfpTransactions:  nil,
			destinationPubkey: validPubKey,
			expectError:       false,
		},
		{
			name:              "empty cpfp transactions",
			cpfpTransactions:  []*pb.UserSignedTxSigningJob{},
			destinationPubkey: validPubKey,
			expectError:       false,
		},
		{
			name:              "nil transaction in cpfp array",
			cpfpTransactions:  []*pb.UserSignedTxSigningJob{nil},
			destinationPubkey: []byte("dest_pubkey"),
			expectError:       true,
			expectedErrMsg:    "cpfp transaction is nil",
		},
		{
			name: "nil signing commitments",
			cpfpTransactions: []*pb.UserSignedTxSigningJob{
				{
					LeafId:             "test-leaf-id",
					SigningCommitments: nil,
				},
			},
			destinationPubkey: []byte("dest_pubkey"),
			expectError:       true,
			expectedErrMsg:    "signing commitments is nil",
		},
		{
			name: "nil signing nonce commitment",
			cpfpTransactions: []*pb.UserSignedTxSigningJob{
				{
					LeafId: "test-leaf-id",
					SigningCommitments: &pb.SigningCommitments{
						SigningCommitments: map[string]*pbcommon.SigningCommitment{},
					},
					SigningNonceCommitment: nil,
				},
			},
			destinationPubkey: []byte("dest_pubkey"),
			expectError:       true,
			expectedErrMsg:    "signing nonce commitment is nil",
		},
		{
			name: "invalid leaf ID format",
			cpfpTransactions: []*pb.UserSignedTxSigningJob{
				{
					LeafId: "invalid-uuid-format",
					SigningCommitments: &pb.SigningCommitments{
						SigningCommitments: map[string]*pbcommon.SigningCommitment{},
					},
					SigningNonceCommitment: &pbcommon.SigningCommitment{},
				},
			},
			destinationPubkey: []byte("dest_pubkey"),
			expectError:       true,
			expectedErrMsg:    "unable to parse node id",
		},
		{
			name: "empty signing commitments map",
			cpfpTransactions: []*pb.UserSignedTxSigningJob{
				{
					LeafId: "550e8400-e29b-41d4-a716-446655440000",
					SigningCommitments: &pb.SigningCommitments{
						SigningCommitments: map[string]*pbcommon.SigningCommitment{}, // empty map
					},
					SigningNonceCommitment: &pbcommon.SigningCommitment{},
				},
			},
			destinationPubkey: []byte("dest_pubkey"),
			expectError:       true,
			expectedErrMsg:    "unable to get node", // Will fail at node lookup
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := lightningHandler.ValidateGetPreimageRequest(
				ctx,
				[]byte("payment_hash"),
				tt.cpfpTransactions,
				tt.directTransactions,
				tt.directFromCpfpTransactions,
				&pb.InvoiceAmount{ValueSats: 1000},
				tt.destinationPubkey,
				0,
				pb.InitiatePreimageSwapRequest_REASON_SEND,
				false,
			)

			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedErrMsg != "" {
					assert.Contains(t, err.Error(), tt.expectedErrMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestInitiatePreimageSwapEdgeCases(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, dbCtx := db.NewTestSQLiteContext(t, ctx)
	defer dbCtx.Close()

	config := &so.Config{}
	lightningHandler := handler.NewLightningHandler(config)

	tests := []struct {
		name           string
		setupRequest   func() *pb.InitiatePreimageSwapRequest
		expectError    bool
		expectedErrMsg string
	}{
		{
			name: "nil transfer",
			setupRequest: func() *pb.InitiatePreimageSwapRequest {
				return &pb.InitiatePreimageSwapRequest{
					Transfer: nil, // nil transfer
				}
			},
			expectError:    true,
			expectedErrMsg: "transfer is required",
		},
		{
			name: "empty leaves to send",
			setupRequest: func() *pb.InitiatePreimageSwapRequest {
				return &pb.InitiatePreimageSwapRequest{
					Transfer: &pb.StartUserSignedTransferRequest{
						LeavesToSend: []*pb.UserSignedTxSigningJob{}, // empty
					},
				}
			},
			expectError:    true,
			expectedErrMsg: "at least one cpfp leaf tx must be provided",
		},
		{
			name: "nil owner identity public key",
			setupRequest: func() *pb.InitiatePreimageSwapRequest {
				return &pb.InitiatePreimageSwapRequest{
					Transfer: &pb.StartUserSignedTransferRequest{
						LeavesToSend: []*pb.UserSignedTxSigningJob{
							{LeafId: "test-leaf"},
						},
						OwnerIdentityPublicKey: nil, // nil owner identity key
					},
				}
			},
			expectError:    true,
			expectedErrMsg: "owner identity public key is required",
		},
		{
			name: "nil receiver identity public key",
			setupRequest: func() *pb.InitiatePreimageSwapRequest {
				return &pb.InitiatePreimageSwapRequest{
					Transfer: &pb.StartUserSignedTransferRequest{
						LeavesToSend: []*pb.UserSignedTxSigningJob{
							{LeafId: "test-leaf"},
						},
						OwnerIdentityPublicKey:    []byte("owner_key"),
						ReceiverIdentityPublicKey: nil, // nil receiver identity key
					},
				}
			},
			expectError:    true,
			expectedErrMsg: "receiver identity public key is required",
		},
		{
			name: "fee not allowed for receive",
			setupRequest: func() *pb.InitiatePreimageSwapRequest {
				return &pb.InitiatePreimageSwapRequest{
					Transfer: &pb.StartUserSignedTransferRequest{
						LeavesToSend: []*pb.UserSignedTxSigningJob{
							{LeafId: "test-leaf"},
						},
						OwnerIdentityPublicKey:    []byte("owner_key"),
						ReceiverIdentityPublicKey: []byte("receiver_key"),
					},
					Reason:  pb.InitiatePreimageSwapRequest_REASON_RECEIVE,
					FeeSats: 100, // fee not allowed for receive
				}
			},
			expectError:    true,
			expectedErrMsg: "fee is not allowed for receive preimage swap",
		},
		{
			name: "nil leaves to send",
			setupRequest: func() *pb.InitiatePreimageSwapRequest {
				return &pb.InitiatePreimageSwapRequest{
					Transfer: &pb.StartUserSignedTransferRequest{
						LeavesToSend:              nil, // nil instead of empty
						OwnerIdentityPublicKey:    []byte("owner_key"),
						ReceiverIdentityPublicKey: []byte("receiver_key"),
					},
				}
			},
			expectError:    true,
			expectedErrMsg: "at least one cpfp leaf tx must be provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupRequest()

			resp, err := lightningHandler.InitiatePreimageSwap(ctx, req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				assert.Contains(t, err.Error(), tt.expectedErrMsg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
			}
		})
	}
}
