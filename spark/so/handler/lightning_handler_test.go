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
