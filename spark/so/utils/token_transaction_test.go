package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/lightsparkdev/spark/common/keys"
	"github.com/stretchr/testify/require"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/google/go-cmp/cmp"
	"github.com/lightsparkdev/spark/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Test constants for consistent test data across all hash tests
var (
	testTokenPublicKey = []byte{
		242, 155, 208, 90, 72, 211, 120, 244, 69, 99, 28, 101, 149, 222, 123, 50,
		252, 63, 99, 54, 137, 226, 7, 224, 163, 122, 93, 248, 42, 159, 173, 45,
	}

	testIdentityPubKey = []byte{
		25, 155, 208, 90, 72, 211, 120, 244, 69, 99, 28, 101, 149, 222, 123, 50,
		252, 63, 99, 54, 137, 226, 7, 224, 163, 122, 93, 248, 42, 159, 173, 46,
	}

	testRevocationPubKey = []byte{
		100, 155, 208, 90, 72, 211, 120, 244, 69, 99, 28, 101, 149, 222, 123, 50,
		252, 63, 99, 54, 137, 226, 7, 224, 163, 122, 93, 248, 42, 159, 173, 46,
	}

	testSparkOperatorPubKey = []byte{
		200, 155, 208, 90, 72, 211, 120, 244, 69, 99, 28, 101, 149, 222, 123, 50,
		252, 63, 99, 54, 137, 226, 7, 224, 163, 122, 93, 248, 42, 159, 173, 46,
	}
	seededRng = rand.NewChaCha8([32]byte{})
)

type testTokenTransactionData struct {
	tokenPublicKey   []byte
	identityPubKey   []byte
	revocationPubKey []byte
	operatorPubKey   []byte
	leafID           string
	bondSats         uint64
	locktime         uint64
	tokenAmount      []byte
	maxSupply        []byte
	tokenName        string
	tokenTicker      string
	decimals         uint32
	issuerTimestamp  uint64
	clientTimestamp  uint64
	expiryTime       uint64
	prevTxHash       [32]byte
	tokenIdentifier  []byte
}

var testData = testTokenTransactionData{
	tokenPublicKey:   testTokenPublicKey,
	identityPubKey:   testIdentityPubKey,
	revocationPubKey: testRevocationPubKey,
	operatorPubKey:   testSparkOperatorPubKey,
	leafID:           "db1a4e48-0fc5-4f6c-8a80-d9d6c561a436",
	bondSats:         10000,
	locktime:         100,
	tokenAmount:      []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 232}, // 1000 in BE format
	maxSupply:        []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 232}, // 1000 in BE format
	tokenName:        "TestToken",
	tokenTicker:      "TEST",
	decimals:         8,
	issuerTimestamp:  100,
	clientTimestamp:  100,
	expiryTime:       0,
	prevTxHash:       sha256.Sum256([]byte("previous transaction")),
	tokenIdentifier:  bytes.Repeat([]byte{0x07}, 32),
}

func createTestTransactions() (*tokenpb.TokenTransaction, *pb.TokenTransaction) {
	tokenTx := &tokenpb.TokenTransaction{
		TokenInputs: &tokenpb.TokenTransaction_MintInput{
			MintInput: &tokenpb.TokenMintInput{
				IssuerPublicKey: testData.tokenPublicKey,
			},
		},
		TokenOutputs: []*tokenpb.TokenOutput{
			{
				Id:                            &testData.leafID,
				OwnerPublicKey:                testData.identityPubKey,
				TokenPublicKey:                testData.tokenPublicKey,
				TokenAmount:                   testData.tokenAmount,
				RevocationCommitment:          testData.identityPubKey,
				WithdrawBondSats:              &testData.bondSats,
				WithdrawRelativeBlockLocktime: &testData.locktime,
			},
		},
		SparkOperatorIdentityPublicKeys: [][]byte{testData.operatorPubKey},
		Network:                         pb.Network_REGTEST,
		Version:                         0,
		ClientCreatedTimestamp:          timestamppb.New(time.UnixMilli(100)),
	}

	sparkTx := &pb.TokenTransaction{
		TokenInputs: &pb.TokenTransaction_MintInput{
			MintInput: &pb.TokenMintInput{
				IssuerPublicKey:         testData.tokenPublicKey,
				IssuerProvidedTimestamp: 100,
			},
		},
		TokenOutputs: []*pb.TokenOutput{
			{
				Id:                            &testData.leafID,
				OwnerPublicKey:                testData.identityPubKey,
				TokenPublicKey:                testData.tokenPublicKey,
				TokenAmount:                   testData.tokenAmount,
				RevocationCommitment:          testData.identityPubKey,
				WithdrawBondSats:              &testData.bondSats,
				WithdrawRelativeBlockLocktime: &testData.locktime,
			},
		},
		SparkOperatorIdentityPublicKeys: [][]byte{testData.operatorPubKey},
		Network:                         pb.Network_REGTEST,
	}

	return tokenTx, sparkTx
}

func TestHashTokenTransactionV0MintLegacyVector(t *testing.T) {
	tokenPublicKey := []byte{
		242, 155, 208, 90, 72, 211, 120, 244, 69, 99, 28, 101, 149, 222, 123, 50,
		252, 63, 99, 54, 137, 226, 7, 224, 163, 122, 93, 248, 42, 159, 173, 45,
	}

	identityPubKey := []byte{
		25, 155, 208, 90, 72, 211, 120, 244, 69, 99, 28, 101, 149, 222, 123, 50,
		252, 63, 99, 54, 137, 226, 7, 224, 163, 122, 93, 248, 42, 159, 173, 46,
	}

	leafID := "db1a4e48-0fc5-4f6c-8a80-d9d6c561a436"
	bondSats := uint64(10000)
	locktime := uint64(100)

	// Create the token transaction matching the JavaScript object
	partialTokenTransaction := &pb.TokenTransaction{
		TokenInputs: &pb.TokenTransaction_MintInput{
			MintInput: &pb.TokenMintInput{
				IssuerPublicKey:         tokenPublicKey,
				IssuerProvidedTimestamp: 100,
			},
		},
		TokenOutputs: []*pb.TokenOutput{
			{
				Id:                            &leafID,
				OwnerPublicKey:                identityPubKey,
				TokenPublicKey:                tokenPublicKey,
				TokenAmount:                   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 232}, // 1000n in BE format
				RevocationCommitment:          identityPubKey,
				WithdrawBondSats:              &bondSats,
				WithdrawRelativeBlockLocktime: &locktime,
			},
		},
		SparkOperatorIdentityPublicKeys: [][]byte{},
		Network:                         pb.Network_REGTEST,
	}

	hash, err := HashTokenTransactionV0(partialTokenTransaction, false)
	if err != nil {
		t.Fatalf("failed to hash token transaction: %v", err)
	}

	want := []byte{
		66, 235, 134, 101, 172, 110, 147, 77, 122, 48, 86, 240, 239, 9, 163, 82,
		120, 234, 246, 206, 245, 242, 186, 180, 154, 41, 207, 179, 194, 31, 211, 36,
	}
	if diff := cmp.Diff(want, hash); diff != "" {
		t.Errorf("hash mismatch (-want +got):\n%s", diff)
	}
}

func TestHashTokenTransactionMintV0(t *testing.T) {
	partialTokenTransaction := &pb.TokenTransaction{
		TokenInputs: &pb.TokenTransaction_MintInput{
			MintInput: &pb.TokenMintInput{
				IssuerPublicKey:         testTokenPublicKey,
				IssuerProvidedTimestamp: testData.issuerTimestamp,
			},
		},
		TokenOutputs: []*pb.TokenOutput{
			{
				Id:                            &testData.leafID,
				OwnerPublicKey:                testIdentityPubKey,
				TokenPublicKey:                testTokenPublicKey,
				TokenAmount:                   testData.tokenAmount,
				RevocationCommitment:          testRevocationPubKey,
				WithdrawBondSats:              &testData.bondSats,
				WithdrawRelativeBlockLocktime: &testData.locktime,
			},
		},
		SparkOperatorIdentityPublicKeys: [][]byte{testSparkOperatorPubKey},
		Network:                         pb.Network_REGTEST,
	}

	hash, err := HashTokenTransactionV0(partialTokenTransaction, false)
	if err != nil {
		t.Fatalf("failed to hash token transaction: %v", err)
	}

	want := []byte{
		56, 47, 132, 171, 2, 236, 10, 72, 214, 89, 28, 46, 171, 39, 221, 113,
		162, 74, 170, 64, 160, 91, 11, 201, 45, 35, 67, 179, 199, 130, 116, 69,
	}
	if diff := cmp.Diff(want, hash); diff != "" {
		t.Errorf("hash mismatch (-want +got):\n%s", diff)
	}
}

func TestHashTokenTransactionCreateV0(t *testing.T) {
	createTransaction := &pb.TokenTransaction{
		TokenInputs: &pb.TokenTransaction_CreateInput{
			CreateInput: &pb.TokenCreateInput{
				IssuerPublicKey: testTokenPublicKey,
				TokenName:       testData.tokenName,
				TokenTicker:     testData.tokenTicker,
				Decimals:        testData.decimals,
				MaxSupply:       testData.maxSupply,
				IsFreezable:     false,
			},
		},
		TokenOutputs:                    []*pb.TokenOutput{},
		SparkOperatorIdentityPublicKeys: [][]byte{testSparkOperatorPubKey},
		Network:                         pb.Network_REGTEST,
	}

	hash, err := HashTokenTransactionV0(createTransaction, false)
	if err != nil {
		t.Fatalf("failed to hash V0 create transaction: %v", err)
	}

	want := []byte{
		35, 118, 177, 53, 49, 47, 174, 59, 123, 2, 212, 38, 217, 133, 124, 232,
		93, 185, 248, 87, 146, 123, 157, 10, 6, 111, 79, 183, 185, 175, 45, 224,
	}
	if diff := cmp.Diff(want, hash); diff != "" {
		t.Errorf("hash mismatch (-want +got):\n%s", diff)
		t.Logf("Actual hash: %x", hash)
	}
}

func TestHashTokenTransactionTransferV0(t *testing.T) {
	// Create V0 transfer transaction
	transferTransaction := &pb.TokenTransaction{
		TokenInputs: &pb.TokenTransaction_TransferInput{
			TransferInput: &pb.TokenTransferInput{
				OutputsToSpend: []*pb.TokenOutputToSpend{
					{
						PrevTokenTransactionHash: testData.prevTxHash[:],
						PrevTokenTransactionVout: 0,
					},
				},
			},
		},
		TokenOutputs: []*pb.TokenOutput{
			{
				Id:                            &testData.leafID,
				OwnerPublicKey:                testIdentityPubKey,
				TokenPublicKey:                testTokenPublicKey,
				TokenAmount:                   testData.tokenAmount,
				RevocationCommitment:          testData.revocationPubKey,
				WithdrawBondSats:              &testData.bondSats,
				WithdrawRelativeBlockLocktime: &testData.locktime,
			},
		},
		SparkOperatorIdentityPublicKeys: [][]byte{testSparkOperatorPubKey},
		Network:                         pb.Network_REGTEST,
	}

	hash, err := HashTokenTransactionV0(transferTransaction, false)
	if err != nil {
		t.Fatalf("failed to hash V0 transfer transaction: %v", err)
	}

	want := []byte{
		68, 88, 168, 87, 42, 251, 11, 182, 69, 202, 46, 202, 39, 234, 196, 201,
		24, 52, 213, 56, 151, 103, 99, 110, 211, 237, 148, 78, 216, 146, 143, 131,
	}
	if diff := cmp.Diff(want, hash); diff != "" {
		t.Errorf("hash mismatch (-want +got):\n%s", diff)
		t.Logf("Actual hash: %x", hash)
	}
}

// TestHashTokenTransactionV0Nil ensures an error is returned when HashTokenTransaction is called with a nil transaction.
func TestHashTokenTransactionV0Nil(t *testing.T) {
	_, err := HashTokenTransactionV0(nil, false)
	if err == nil {
		t.Errorf("expected an error for nil token transaction, but got nil")
	}
}

// TestHashTokenTransactionV0Empty checks that hashing an empty transaction does not produce an error.
func TestHashTokenTransactionV0Empty(t *testing.T) {
	tx := &pb.TokenTransaction{
		TokenInputs:                     &pb.TokenTransaction_MintInput{},
		TokenOutputs:                    []*pb.TokenOutput{},
		SparkOperatorIdentityPublicKeys: [][]byte{},
	}
	_, err := HashTokenTransactionV0(tx, false)
	if err == nil {
		t.Errorf("expected error for empty transaction, got nil")
	}
	if !strings.Contains(err.Error(), "token transaction must have exactly one of create_input, mint_input, or transfer_input") {
		t.Errorf("expected error about input types, got: %v", err)
	}
}

// TestHashTokenTransactionV0UniqueHash checks that hashing a valid token transaction does not produce an error
// and that when a field is changed, the hash changes.
func TestHashTokenTransactionV0UniqueHash(t *testing.T) {
	operatorKeys := [][]byte{
		bytes.Repeat([]byte{0x04}, 32),
		bytes.Repeat([]byte{0x05}, 32),
		bytes.Repeat([]byte{0x06}, 32),
	}

	partialMintTokenTransaction := &pb.TokenTransaction{
		TokenInputs: &pb.TokenTransaction_MintInput{
			MintInput: &pb.TokenMintInput{
				IssuerPublicKey: bytes.Repeat([]byte{0x01}, 32),
			},
		},
		TokenOutputs: []*pb.TokenOutput{
			{
				OwnerPublicKey: bytes.Repeat([]byte{0x01}, 32),
				TokenPublicKey: bytes.Repeat([]byte{0x02}, 32),
				TokenAmount:    []byte{0x01},
			},
		},
		SparkOperatorIdentityPublicKeys: operatorKeys,
	}

	partialTransferTokenTransaction := &pb.TokenTransaction{
		TokenInputs: &pb.TokenTransaction_TransferInput{
			TransferInput: &pb.TokenTransferInput{
				OutputsToSpend: []*pb.TokenOutputToSpend{
					{
						PrevTokenTransactionHash: bytes.Repeat([]byte{0x01}, 32),
						PrevTokenTransactionVout: 1,
					},
				},
			},
		},
		TokenOutputs: []*pb.TokenOutput{
			{
				OwnerPublicKey: bytes.Repeat([]byte{0x01}, 32),
				TokenPublicKey: bytes.Repeat([]byte{0x02}, 32),
				TokenAmount:    []byte{0x01},
			},
		},
		SparkOperatorIdentityPublicKeys: operatorKeys,
	}

	outputID := "test-output-1"
	bondSats := uint64(1000000)
	blockLocktime := uint64(1000)
	finalMintTokenTransaction := proto.Clone(partialMintTokenTransaction).(*pb.TokenTransaction)
	finalMintTokenTransaction.TokenOutputs[0].Id = &outputID
	finalMintTokenTransaction.TokenOutputs[0].RevocationCommitment = bytes.Repeat([]byte{0x03}, 32)
	finalMintTokenTransaction.TokenOutputs[0].WithdrawBondSats = &bondSats
	finalMintTokenTransaction.TokenOutputs[0].WithdrawRelativeBlockLocktime = &blockLocktime

	finalTransferTokenTransaction := proto.Clone(partialTransferTokenTransaction).(*pb.TokenTransaction)
	finalTransferTokenTransaction.TokenOutputs[0].Id = &outputID
	finalTransferTokenTransaction.TokenOutputs[0].RevocationCommitment = bytes.Repeat([]byte{0x03}, 32)
	finalTransferTokenTransaction.TokenOutputs[0].WithdrawBondSats = &bondSats
	finalTransferTokenTransaction.TokenOutputs[0].WithdrawRelativeBlockLocktime = &blockLocktime

	// Hash all transactions
	partialMintHash, err := HashTokenTransactionV0(partialMintTokenTransaction, true)
	if err != nil {
		t.Fatalf("failed to hash partial issuance transaction: %v", err)
	}

	partialTransferHash, err := HashTokenTransactionV0(partialTransferTokenTransaction, true)
	if err != nil {
		t.Fatalf("failed to hash partial transfer transaction: %v", err)
	}

	finalMintHash, err := HashTokenTransactionV0(finalMintTokenTransaction, false)
	if err != nil {
		t.Fatalf("failed to hash final issuance transaction: %v", err)
	}

	finalTransferHash, err := HashTokenTransactionV0(finalTransferTokenTransaction, false)
	if err != nil {
		t.Fatalf("failed to hash final transfer transaction: %v", err)
	}

	// Create map to check for duplicates
	hashes := map[string]string{
		"partialMint":     hex.EncodeToString(partialMintHash),
		"partialTransfer": hex.EncodeToString(partialTransferHash),
		"finalMint":       hex.EncodeToString(finalMintHash),
		"finalTransfer":   hex.EncodeToString(finalTransferHash),
	}

	// Check that all hashes are unique
	seen := make(map[string]bool)
	for name, hash := range hashes {
		if seen[hash] {
			t.Errorf("duplicate hash detected for %s", name)
		}
		seen[hash] = true
	}
}

// TestHashTokenTransactionV1Nil ensures an error is returned when HashTokenTransaction is called with a nil transaction.
func TestHashTokenTransactionV1Nil(t *testing.T) {
	_, err := HashTokenTransactionV1(nil, false)
	if err == nil {
		t.Errorf("expected an error for nil token transaction, but got nil")
	}
}

// TestHashTokenTransactionV1Empty checks that hashing an empty transaction does not produce an error.
func TestHashTokenTransactionV1Empty(t *testing.T) {
	tx := &tokenpb.TokenTransaction{
		Version: 1,
		TokenInputs: &tokenpb.TokenTransaction_MintInput{
			MintInput: &tokenpb.TokenMintInput{
				IssuerPublicKey: bytes.Repeat([]byte{0x01}, 32),
			},
		},
		TokenOutputs:                    []*tokenpb.TokenOutput{},
		SparkOperatorIdentityPublicKeys: [][]byte{},
		ClientCreatedTimestamp:          timestamppb.New(time.Unix(0, 0)),
		ExpiryTime:                      timestamppb.New(time.Unix(0, 0)),
	}
	hash, err := HashTokenTransactionV1(tx, false)
	if err != nil {
		t.Errorf("expected no error for empty transaction, got: %v", err)
	}
	if len(hash) == 0 {
		t.Errorf("expected a non-empty hash")
	}
}

// TestHashTokenTransactionV1UniqueHash checks that hashing a valid token transaction does not produce an error
// and that when a field is changed, the hash changes.
func TestHashTokenTransactionV1UniqueHash(t *testing.T) {
	operatorKeys := [][]byte{
		bytes.Repeat([]byte{0x04}, 32),
		bytes.Repeat([]byte{0x05}, 32),
		bytes.Repeat([]byte{0x06}, 32),
	}

	partialMintTokenTransaction := &tokenpb.TokenTransaction{
		Version: 1,
		TokenInputs: &tokenpb.TokenTransaction_MintInput{
			MintInput: &tokenpb.TokenMintInput{
				IssuerPublicKey: bytes.Repeat([]byte{0x01}, 32),
			},
		},
		TokenOutputs: []*tokenpb.TokenOutput{
			{
				OwnerPublicKey: bytes.Repeat([]byte{0x01}, 32),
				TokenPublicKey: bytes.Repeat([]byte{0x02}, 32),
				TokenAmount:    []byte{0x01},
			},
		},
		SparkOperatorIdentityPublicKeys: operatorKeys,
		ClientCreatedTimestamp:          timestamppb.New(time.Unix(0, 0)),
	}

	partialTransferTokenTransaction := &tokenpb.TokenTransaction{
		Version: 1,
		TokenInputs: &tokenpb.TokenTransaction_TransferInput{
			TransferInput: &tokenpb.TokenTransferInput{
				OutputsToSpend: []*tokenpb.TokenOutputToSpend{
					{
						PrevTokenTransactionHash: bytes.Repeat([]byte{0x01}, 32),
						PrevTokenTransactionVout: 1,
					},
				},
			},
		},
		TokenOutputs: []*tokenpb.TokenOutput{
			{
				OwnerPublicKey: bytes.Repeat([]byte{0x01}, 32),
				TokenPublicKey: bytes.Repeat([]byte{0x02}, 32),
				TokenAmount:    []byte{0x01},
			},
		},
		SparkOperatorIdentityPublicKeys: operatorKeys,
		ClientCreatedTimestamp:          timestamppb.New(time.Unix(0, 0)),
	}

	outputID := "test-output-1"
	bondSats := uint64(1000000)
	blockLocktime := uint64(1000)
	finalMintTokenTransaction := proto.Clone(partialMintTokenTransaction).(*tokenpb.TokenTransaction)
	finalMintTokenTransaction.TokenOutputs[0].Id = &outputID
	finalMintTokenTransaction.TokenOutputs[0].RevocationCommitment = bytes.Repeat([]byte{0x03}, 32)
	finalMintTokenTransaction.TokenOutputs[0].WithdrawBondSats = &bondSats
	finalMintTokenTransaction.TokenOutputs[0].WithdrawRelativeBlockLocktime = &blockLocktime
	finalMintTokenTransaction.ExpiryTime = timestamppb.New(time.Unix(1000, 0))

	finalTransferTokenTransaction := proto.Clone(partialTransferTokenTransaction).(*tokenpb.TokenTransaction)
	finalTransferTokenTransaction.TokenOutputs[0].Id = &outputID
	finalTransferTokenTransaction.TokenOutputs[0].RevocationCommitment = bytes.Repeat([]byte{0x03}, 32)
	finalTransferTokenTransaction.TokenOutputs[0].WithdrawBondSats = &bondSats
	finalTransferTokenTransaction.TokenOutputs[0].WithdrawRelativeBlockLocktime = &blockLocktime
	finalTransferTokenTransaction.ExpiryTime = timestamppb.New(time.Unix(1000, 0))

	// Hash all transactions
	partialMintHash, err := HashTokenTransactionV1(partialMintTokenTransaction, true)
	if err != nil {
		t.Fatalf("failed to hash partial issuance transaction: %v", err)
	}

	partialTransferHash, err := HashTokenTransactionV1(partialTransferTokenTransaction, true)
	if err != nil {
		t.Fatalf("failed to hash partial transfer transaction: %v", err)
	}

	finalMintHash, err := HashTokenTransactionV1(finalMintTokenTransaction, false)
	if err != nil {
		t.Fatalf("failed to hash final issuance transaction: %v", err)
	}

	finalTransferHash, err := HashTokenTransactionV1(finalTransferTokenTransaction, false)
	if err != nil {
		t.Fatalf("failed to hash final transfer transaction: %v", err)
	}

	// Create map to check for duplicates
	hashes := map[string]string{
		"partialMint":     hex.EncodeToString(partialMintHash),
		"partialTransfer": hex.EncodeToString(partialTransferHash),
		"finalMint":       hex.EncodeToString(finalMintHash),
		"finalTransfer":   hex.EncodeToString(finalTransferHash),
	}

	// Check that all hashes are unique
	seen := make(map[string]bool)
	for name, hash := range hashes {
		if seen[hash] {
			t.Errorf("duplicate hash detected for %s", name)
		}
		seen[hash] = true
	}
}

func TestHashTokenTransactionMintV1(t *testing.T) {
	partialTokenTransaction := &tokenpb.TokenTransaction{
		Version: 1,
		TokenInputs: &tokenpb.TokenTransaction_MintInput{
			MintInput: &tokenpb.TokenMintInput{
				IssuerPublicKey: testTokenPublicKey,
				TokenIdentifier: testData.tokenIdentifier,
			},
		},
		TokenOutputs: []*tokenpb.TokenOutput{
			{
				Id:                            &testData.leafID,
				OwnerPublicKey:                testIdentityPubKey,
				TokenPublicKey:                testTokenPublicKey,
				TokenAmount:                   testData.tokenAmount,
				RevocationCommitment:          testRevocationPubKey,
				WithdrawBondSats:              &testData.bondSats,
				WithdrawRelativeBlockLocktime: &testData.locktime,
			},
		},
		SparkOperatorIdentityPublicKeys: [][]byte{testSparkOperatorPubKey},
		Network:                         pb.Network_REGTEST,
		ExpiryTime:                      timestamppb.New(time.UnixMilli(int64(testData.expiryTime))),
		ClientCreatedTimestamp:          timestamppb.New(time.UnixMilli(int64(testData.clientTimestamp))),
	}

	hash, err := HashTokenTransactionV1(partialTokenTransaction, false)
	if err != nil {
		t.Fatalf("failed to hash token transaction: %v", err)
	}

	want := []byte{
		9, 162, 16, 177, 20, 91, 93, 148, 158, 249, 6, 42, 59, 136, 145, 184,
		202, 35, 243, 228, 14, 231, 132, 201, 66, 137, 201, 76, 97, 186, 149, 172,
	}
	if diff := cmp.Diff(want, hash); diff != "" {
		t.Errorf("hash mismatch (-want +got):\n%s", diff)
	}
}

func TestHashTokenTransactionCreateV1(t *testing.T) {
	// Create V1 token transaction
	createTransaction := &tokenpb.TokenTransaction{
		Version: 1,
		TokenInputs: &tokenpb.TokenTransaction_CreateInput{
			CreateInput: &tokenpb.TokenCreateInput{
				IssuerPublicKey: testTokenPublicKey,
				TokenName:       testData.tokenName,
				TokenTicker:     testData.tokenTicker,
				Decimals:        testData.decimals,
				MaxSupply:       testData.maxSupply,
				IsFreezable:     false,
			},
		},
		TokenOutputs:                    []*tokenpb.TokenOutput{},
		SparkOperatorIdentityPublicKeys: [][]byte{testSparkOperatorPubKey},
		Network:                         pb.Network_REGTEST,
		ExpiryTime:                      timestamppb.New(time.UnixMilli(int64(testData.expiryTime))),
		ClientCreatedTimestamp:          timestamppb.New(time.UnixMilli(int64(testData.clientTimestamp))),
	}

	hash, err := HashTokenTransactionV1(createTransaction, false)
	if err != nil {
		t.Fatalf("failed to hash create transaction: %v", err)
	}

	// Expected hash for V1 create transaction
	want := []byte{
		201, 249, 88, 215, 6, 7, 221, 209, 103, 153, 36, 41, 19, 60, 80, 144,
		153, 159, 185, 61, 20, 117, 87, 196, 102, 151, 76, 4, 191, 121, 221, 182,
	}
	if diff := cmp.Diff(want, hash); diff != "" {
		t.Errorf("hash mismatch (-want +got):\n%s", diff)
		t.Logf("Actual hash: %x", hash)
	}
}

func TestHashTokenTransactionTransferV1(t *testing.T) {
	transferTransaction := &tokenpb.TokenTransaction{
		Version: 1,
		TokenInputs: &tokenpb.TokenTransaction_TransferInput{
			TransferInput: &tokenpb.TokenTransferInput{
				OutputsToSpend: []*tokenpb.TokenOutputToSpend{
					{
						PrevTokenTransactionHash: testData.prevTxHash[:],
						PrevTokenTransactionVout: 0,
					},
				},
			},
		},
		TokenOutputs: []*tokenpb.TokenOutput{
			{
				Id:                            &testData.leafID,
				OwnerPublicKey:                testIdentityPubKey,
				TokenPublicKey:                testTokenPublicKey,
				TokenAmount:                   testData.tokenAmount,
				RevocationCommitment:          testData.revocationPubKey,
				WithdrawBondSats:              &testData.bondSats,
				WithdrawRelativeBlockLocktime: &testData.locktime,
			},
		},
		SparkOperatorIdentityPublicKeys: [][]byte{testSparkOperatorPubKey},
		Network:                         pb.Network_REGTEST,
		ExpiryTime:                      timestamppb.New(time.UnixMilli(int64(testData.expiryTime))),
		ClientCreatedTimestamp:          timestamppb.New(time.UnixMilli(int64(testData.clientTimestamp))),
	}

	hash, err := HashTokenTransactionV1(transferTransaction, false)
	if err != nil {
		t.Fatalf("failed to hash transfer transaction: %v", err)
	}

	want := []byte{
		86, 89, 220, 198, 197, 223, 236, 142, 73, 125, 112, 186, 29, 1, 26, 203,
		126, 154, 255, 176, 237, 210, 171, 98, 211, 130, 138, 113, 128, 129, 227, 35,
	}
	if diff := cmp.Diff(want, hash); diff != "" {
		t.Errorf("hash mismatch (-want +got):\n%s", diff)
		t.Logf("Actual hash: %x", hash)
	}
}

func TestHashTokenTransactionV1RequiredFields(t *testing.T) {
	prevTxHash := sha256.Sum256([]byte("previous transaction"))

	// Create base valid transactions for each type
	baseMintTransaction := &tokenpb.TokenTransaction{
		Version: 1,
		TokenInputs: &tokenpb.TokenTransaction_MintInput{
			MintInput: &tokenpb.TokenMintInput{
				IssuerPublicKey: testTokenPublicKey,
			},
		},
		TokenOutputs: []*tokenpb.TokenOutput{
			{
				Id:                            &testData.leafID,
				OwnerPublicKey:                testIdentityPubKey,
				TokenPublicKey:                testTokenPublicKey,
				TokenAmount:                   testData.tokenAmount,
				RevocationCommitment:          testIdentityPubKey,
				WithdrawBondSats:              &testData.bondSats,
				WithdrawRelativeBlockLocktime: &testData.locktime,
			},
		},
		SparkOperatorIdentityPublicKeys: [][]byte{testSparkOperatorPubKey},
		Network:                         pb.Network_REGTEST,
		ExpiryTime:                      timestamppb.New(time.UnixMilli(int64(testData.expiryTime))),
		ClientCreatedTimestamp:          timestamppb.New(time.UnixMilli(int64(testData.clientTimestamp))),
	}

	baseTransferTransaction := &tokenpb.TokenTransaction{
		Version: 1,
		TokenInputs: &tokenpb.TokenTransaction_TransferInput{
			TransferInput: &tokenpb.TokenTransferInput{
				OutputsToSpend: []*tokenpb.TokenOutputToSpend{
					{
						PrevTokenTransactionHash: prevTxHash[:],
						PrevTokenTransactionVout: 0,
					},
				},
			},
		},
		TokenOutputs: []*tokenpb.TokenOutput{
			{
				OwnerPublicKey: testIdentityPubKey,
				TokenPublicKey: testTokenPublicKey,
				TokenAmount:    testData.tokenAmount,
			},
		},
		SparkOperatorIdentityPublicKeys: [][]byte{testSparkOperatorPubKey},
		Network:                         pb.Network_REGTEST,
		ExpiryTime:                      timestamppb.New(time.UnixMilli(int64(testData.expiryTime))),
		ClientCreatedTimestamp:          timestamppb.New(time.UnixMilli(int64(testData.clientTimestamp))),
	}

	baseCreateTransaction := &tokenpb.TokenTransaction{
		Version: 1,
		TokenInputs: &tokenpb.TokenTransaction_CreateInput{
			CreateInput: &tokenpb.TokenCreateInput{
				IssuerPublicKey: testTokenPublicKey,
				TokenName:       testData.tokenName,
				TokenTicker:     testData.tokenTicker,
				Decimals:        testData.decimals,
				MaxSupply:       testData.maxSupply,
				IsFreezable:     false,
			},
		},
		TokenOutputs: []*tokenpb.TokenOutput{
			{
				OwnerPublicKey: testIdentityPubKey,
				TokenPublicKey: testTokenPublicKey,
				TokenAmount:    testData.tokenAmount,
			},
		},
		SparkOperatorIdentityPublicKeys: [][]byte{testSparkOperatorPubKey},
		Network:                         pb.Network_REGTEST,
		ExpiryTime:                      timestamppb.New(time.UnixMilli(int64(testData.expiryTime))),
		ClientCreatedTimestamp:          timestamppb.New(time.UnixMilli(int64(testData.clientTimestamp))),
	}

	tests := []struct {
		name        string
		txType      string
		baseTx      *tokenpb.TokenTransaction
		modifyTx    func(*tokenpb.TokenTransaction)
		expectedErr string
	}{
		// Common field tests (apply to all transaction types)
		{
			name:   "nil client created timestamp",
			txType: "mint",
			baseTx: baseMintTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.ClientCreatedTimestamp = nil
			},
			expectedErr: "client created timestamp cannot be empty",
		},
		{
			name:   "nil spark operator identity public keys",
			txType: "mint",
			baseTx: baseMintTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.SparkOperatorIdentityPublicKeys = nil
			},
			expectedErr: "operator public keys cannot be nil",
		},
		{
			name:   "nil token output owner public key",
			txType: "mint",
			baseTx: baseMintTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.TokenOutputs[0].OwnerPublicKey = nil
			},
			expectedErr: "owner public key at index 0 cannot be nil or empty",
		},
		{
			name:   "empty token output id",
			txType: "mint",
			baseTx: baseMintTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				emptyString := ""
				tx.TokenOutputs[0].Id = &emptyString
			},
			expectedErr: "token output ID at index 0 cannot be nil or empty",
		},
		{
			name:   "nil token output id",
			txType: "mint",
			baseTx: baseMintTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.TokenOutputs[0].Id = nil
			},
			expectedErr: "token output ID at index 0 cannot be nil or empty",
		},
		{
			name:   "nil token output token amount",
			txType: "mint",
			baseTx: baseMintTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.TokenOutputs[0].TokenAmount = nil
			},
			expectedErr: "token amount at index 0 cannot be nil or empty",
		},
		{
			name:   "empty token output token amount",
			txType: "mint",
			baseTx: baseMintTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.TokenOutputs[0].TokenAmount = []byte{}
			},
			expectedErr: "token amount at index 0 cannot be nil or empty",
		},
		{
			name:   "nil spark operator public key",
			txType: "mint",
			baseTx: baseMintTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.SparkOperatorIdentityPublicKeys = [][]byte{nil}
			},
			expectedErr: "operator public key at index 0 cannot be nil",
		},
		{
			name:   "empty spark operator public key",
			txType: "mint",
			baseTx: baseMintTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.SparkOperatorIdentityPublicKeys = [][]byte{{}}
			},
			expectedErr: "operator public key at index 0 cannot be empty",
		},

		// Mint-specific tests
		{
			name:   "nil mint input issuer public key",
			txType: "mint",
			baseTx: baseMintTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.TokenInputs = &tokenpb.TokenTransaction_MintInput{
					MintInput: &tokenpb.TokenMintInput{
						IssuerPublicKey: nil,
					},
				}
			},
			expectedErr: "issuer public key cannot be nil or empty",
		},
		{
			name:   "empty mint input issuer public key",
			txType: "mint",
			baseTx: baseMintTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.TokenInputs = &tokenpb.TokenTransaction_MintInput{
					MintInput: &tokenpb.TokenMintInput{
						IssuerPublicKey: []byte{},
					},
				}
			},
			expectedErr: "issuer public key cannot be nil or empty",
		},

		// Transfer-specific tests
		{
			name:   "nil transfer input outputs to spend",
			txType: "transfer",
			baseTx: baseTransferTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.TokenInputs = &tokenpb.TokenTransaction_TransferInput{
					TransferInput: &tokenpb.TokenTransferInput{
						OutputsToSpend: nil,
					},
				}
			},
			expectedErr: "transfer input outputs cannot be nil",
		},
		{
			name:   "nil output to spend",
			txType: "transfer",
			baseTx: baseTransferTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.TokenInputs = &tokenpb.TokenTransaction_TransferInput{
					TransferInput: &tokenpb.TokenTransferInput{
						OutputsToSpend: []*tokenpb.TokenOutputToSpend{nil},
					},
				}
			},
			expectedErr: "transfer input token output at index 0 cannot be nil",
		},
		{
			name:   "invalid previous transaction hash length",
			txType: "transfer",
			baseTx: baseTransferTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.TokenInputs = &tokenpb.TokenTransaction_TransferInput{
					TransferInput: &tokenpb.TokenTransferInput{
						OutputsToSpend: []*tokenpb.TokenOutputToSpend{
							{
								PrevTokenTransactionHash: []byte{1, 2, 3}, // Too short
								PrevTokenTransactionVout: 0,
							},
						},
					},
				}
			},
			expectedErr: "invalid previous transaction hash length at index 0",
		},

		// Create-specific tests
		{
			name:   "nil create input issuer public key",
			txType: "create",
			baseTx: baseCreateTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.TokenInputs = &tokenpb.TokenTransaction_CreateInput{
					CreateInput: &tokenpb.TokenCreateInput{
						IssuerPublicKey: nil,
						TokenName:       "TestToken",
						TokenTicker:     "TEST",
						Decimals:        8,
						MaxSupply:       []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100},
						IsFreezable:     false,
					},
				}
			},
			expectedErr: "issuer public key cannot be nil or empty",
		},
		{
			name:   "empty create input issuer public key",
			txType: "create",
			baseTx: baseCreateTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.TokenInputs = &tokenpb.TokenTransaction_CreateInput{
					CreateInput: &tokenpb.TokenCreateInput{
						IssuerPublicKey: []byte{},
						TokenName:       "TestToken",
						TokenTicker:     "TEST",
						Decimals:        8,
						MaxSupply:       []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100},
						IsFreezable:     false,
					},
				}
			},
			expectedErr: "issuer public key cannot be nil or empty",
		},
		{
			name:   "empty token name",
			txType: "create",
			baseTx: baseCreateTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.TokenInputs = &tokenpb.TokenTransaction_CreateInput{
					CreateInput: &tokenpb.TokenCreateInput{
						IssuerPublicKey: testTokenPublicKey,
						TokenName:       "",
						TokenTicker:     testData.tokenTicker,
						Decimals:        testData.decimals,
						MaxSupply:       testData.maxSupply,
						IsFreezable:     false,
					},
				}
			},
			expectedErr: "token name cannot be empty",
		},
		{
			name:   "empty token ticker",
			txType: "create",
			baseTx: baseCreateTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.TokenInputs = &tokenpb.TokenTransaction_CreateInput{
					CreateInput: &tokenpb.TokenCreateInput{
						IssuerPublicKey: testTokenPublicKey,
						TokenName:       testData.tokenName,
						TokenTicker:     "",
						Decimals:        testData.decimals,
						MaxSupply:       testData.maxSupply,
						IsFreezable:     false,
					},
				}
			},
			expectedErr: "token ticker cannot be empty",
		},
		{
			name:   "nil max supply",
			txType: "create",
			baseTx: baseCreateTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.TokenInputs = &tokenpb.TokenTransaction_CreateInput{
					CreateInput: &tokenpb.TokenCreateInput{
						IssuerPublicKey: testTokenPublicKey,
						TokenName:       testData.tokenName,
						TokenTicker:     testData.tokenTicker,
						Decimals:        testData.decimals,
						MaxSupply:       nil,
						IsFreezable:     false,
					},
				}
			},
			expectedErr: "max supply cannot be nil",
		},
		{
			name:   "max supply wrong length",
			txType: "create",
			baseTx: baseCreateTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.TokenInputs = &tokenpb.TokenTransaction_CreateInput{
					CreateInput: &tokenpb.TokenCreateInput{
						IssuerPublicKey: testTokenPublicKey,
						TokenName:       testData.tokenName,
						TokenTicker:     testData.tokenTicker,
						Decimals:        testData.decimals,
						MaxSupply:       []byte{1, 2, 3, 4, 5}, // Too short
						IsFreezable:     false,
					},
				}
			},
			expectedErr: "max supply must be exactly 16 bytes",
		},
		{
			name:   "max supply too long",
			txType: "create",
			baseTx: baseCreateTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.TokenInputs = &tokenpb.TokenTransaction_CreateInput{
					CreateInput: &tokenpb.TokenCreateInput{
						IssuerPublicKey: testTokenPublicKey,
						TokenName:       testData.tokenName,
						TokenTicker:     testData.tokenTicker,
						Decimals:        testData.decimals,
						MaxSupply:       bytes.Repeat([]byte{1}, 20), // Too long
						IsFreezable:     false,
					},
				}
			},
			expectedErr: "max supply must be exactly 16 bytes",
		},

		// Expiry time tests (for final hash)
		{
			name:   "nil expiry time for final hash",
			txType: "mint",
			baseTx: baseMintTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.ExpiryTime = nil
			},
			expectedErr: "expiry time cannot be empty",
		},
		{
			name:   "nil revocation commitment for final hash",
			txType: "mint",
			baseTx: baseMintTransaction,
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.TokenOutputs[0].RevocationCommitment = nil
			},
			expectedErr: "revocation public key at index 0 cannot be nil or empty",
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.txType, tt.name), func(t *testing.T) {
			tx := proto.Clone(tt.baseTx).(*tokenpb.TokenTransaction)

			tt.modifyTx(tx)

			_, err := HashTokenTransactionV1(tx, false)
			if err == nil {
				t.Fatalf("expected error for %s, but got nil", tt.name)
			}
			if !strings.Contains(err.Error(), tt.expectedErr) {
				t.Errorf("unexpected error message for %s: got %v, want containing %q", tt.name, err, tt.expectedErr)
			}
		})
	}
}

func TestHashTokenTransactionV1PartialHashRequiredFields(t *testing.T) {
	// Create base valid transaction for partial hash testing
	baseTransaction := &tokenpb.TokenTransaction{
		Version: 1,
		TokenInputs: &tokenpb.TokenTransaction_MintInput{
			MintInput: &tokenpb.TokenMintInput{
				IssuerPublicKey: testTokenPublicKey,
			},
		},
		TokenOutputs: []*tokenpb.TokenOutput{
			{
				OwnerPublicKey: testIdentityPubKey,
				TokenPublicKey: testTokenPublicKey,
				TokenAmount:    testData.tokenAmount,
			},
		},
		SparkOperatorIdentityPublicKeys: [][]byte{testSparkOperatorPubKey},
		Network:                         pb.Network_REGTEST,
		ClientCreatedTimestamp:          timestamppb.New(time.UnixMilli(int64(testData.clientTimestamp))),
		// Note: ExpiryTime is intentionally nil for partial hash testing
	}

	tests := []struct {
		name        string
		modifyTx    func(*tokenpb.TokenTransaction)
		expectedErr string
		shouldPass  bool
	}{
		{
			name: "nil expiry time for partial hash should pass",
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.ExpiryTime = nil
			},
			expectedErr: "",
			shouldPass:  true,
		},
		{
			name: "nil client created timestamp for partial hash should fail",
			modifyTx: func(tx *tokenpb.TokenTransaction) {
				tx.ClientCreatedTimestamp = nil
			},
			expectedErr: "client created timestamp cannot be empty",
			shouldPass:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := proto.Clone(baseTransaction).(*tokenpb.TokenTransaction)

			tt.modifyTx(tx)

			_, err := HashTokenTransactionV1(tx, true) // true for partial hash
			if tt.shouldPass {
				if err != nil {
					t.Fatalf("expected no error for %s, but got: %v", tt.name, err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error for %s, but got nil", tt.name)
				}
				if !strings.Contains(err.Error(), tt.expectedErr) {
					t.Errorf("unexpected error message for %s: got %v, want containing %q", tt.name, err, tt.expectedErr)
				}
			}
		})
	}
}

func TestHashTokenTransactionVersioning(t *testing.T) {
	// Create a basic token transaction
	tokenTx := &tokenpb.TokenTransaction{
		TokenInputs: &tokenpb.TokenTransaction_MintInput{
			MintInput: &tokenpb.TokenMintInput{
				IssuerPublicKey: bytes.Repeat([]byte{0x01}, 33),
			},
		},
		TokenOutputs: []*tokenpb.TokenOutput{
			{
				Id:                   &testData.leafID,
				RevocationCommitment: bytes.Repeat([]byte{0x05}, 33),
				OwnerPublicKey:       bytes.Repeat([]byte{0x02}, 33),
				TokenPublicKey:       bytes.Repeat([]byte{0x03}, 33),
				TokenAmount:          []byte{0x01},
			},
		},
		SparkOperatorIdentityPublicKeys: [][]byte{bytes.Repeat([]byte{0x04}, 33)},
		Network:                         pb.Network_REGTEST,
		ClientCreatedTimestamp:          timestamppb.New(time.Unix(0, 0)),
		ExpiryTime:                      timestamppb.New(time.Unix(1000, 0)),
	}

	t.Run("version 0", func(t *testing.T) {
		tokenTx.Version = 0
		hash, err := HashTokenTransaction(tokenTx, false)
		if err != nil {
			t.Errorf("unexpected error for version 0: %v", err)
		}
		if len(hash) == 0 {
			t.Error("expected non-empty hash for version 0")
		}
	})

	t.Run("version 1", func(t *testing.T) {
		tokenTx.Version = 1
		hash, err := HashTokenTransaction(tokenTx, false)
		if err != nil {
			t.Errorf("unexpected error for version 1: %v", err)
		}
		if len(hash) == 0 {
			t.Error("expected non-empty hash for version 1")
		}
	})

	t.Run("nil transaction", func(t *testing.T) {
		_, err := HashTokenTransaction(nil, false)
		if err == nil {
			t.Error("expected error for nil transaction")
		}
		if !strings.Contains(err.Error(), "cannot be nil") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}

func TestHashTokenTransactionProtoEquivalence(t *testing.T) {
	tokenTx, sparkTx := createTestTransactions()

	t.Run("full hash equivalence", func(t *testing.T) {
		tokenHash, err := HashTokenTransaction(tokenTx, false)
		if err != nil {
			t.Fatalf("failed to hash token transaction: %v", err)
		}

		sparkHash, err := HashTokenTransactionV0(sparkTx, false)
		if err != nil {
			t.Fatalf("failed to hash spark transaction: %v", err)
		}

		if !bytes.Equal(tokenHash, sparkHash) {
			t.Errorf("hash mismatch between proto types\ntoken hash: %x\nspark hash: %x", tokenHash, sparkHash)
		}
	})

	t.Run("partial hash equivalence", func(t *testing.T) {
		tokenHash, err := HashTokenTransaction(tokenTx, true)
		if err != nil {
			t.Fatalf("failed to hash token transaction (partial): %v", err)
		}

		sparkHash, err := HashTokenTransactionV0(sparkTx, true)
		if err != nil {
			t.Fatalf("failed to hash spark transaction (partial): %v", err)
		}

		if !bytes.Equal(tokenHash, sparkHash) {
			t.Errorf("hash mismatch between proto types\ntoken hash: %x\nspark hash: %x", tokenHash, sparkHash)
		}
	})
}

func TestHashTokenTransactionPartialVsFull(t *testing.T) {
	tokenTx, sparkTx := createTestTransactions()

	t.Run("token transaction partial vs full", func(t *testing.T) {
		fullHash, err := HashTokenTransaction(tokenTx, false)
		if err != nil {
			t.Fatalf("failed to hash token transaction (full): %v", err)
		}

		partialHash, err := HashTokenTransaction(tokenTx, true)
		if err != nil {
			t.Fatalf("failed to hash token transaction (partial): %v", err)
		}

		if bytes.Equal(fullHash, partialHash) {
			t.Error("full and partial hashes should be different for token transaction")
		}
	})

	t.Run("spark transaction partial vs full", func(t *testing.T) {
		fullHash, err := HashTokenTransactionV0(sparkTx, false)
		if err != nil {
			t.Fatalf("failed to hash spark transaction (full): %v", err)
		}

		partialHash, err := HashTokenTransactionV0(sparkTx, true)
		if err != nil {
			t.Fatalf("failed to hash spark transaction (partial): %v", err)
		}

		if bytes.Equal(fullHash, partialHash) {
			t.Error("full and partial hashes should be different for spark transaction")
		}
	})
}

func TestValidateOwnershipSignature(t *testing.T) {
	privKey, _ := btcec.NewPrivateKey()
	pubKey := privKey.PubKey()
	messageHash := sha256.Sum256([]byte("test message"))
	schnorrSig, _ := schnorr.Sign(privKey, messageHash[:])
	ecdsaSig := ecdsa.Sign(privKey, messageHash[:])

	tests := []struct {
		name               string
		ownershipSignature []byte
		txHash             []byte
		ownerPublicKey     []byte
		wantErr            bool
	}{
		{
			name:               "valid Schnorr signature",
			ownershipSignature: schnorrSig.Serialize(),
			txHash:             messageHash[:],
			ownerPublicKey:     pubKey.SerializeCompressed(),
			wantErr:            false,
		},
		{
			name:               "valid ECDSA DER signature",
			ownershipSignature: ecdsaSig.Serialize(),
			txHash:             messageHash[:],
			ownerPublicKey:     pubKey.SerializeCompressed(),
			wantErr:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateOwnershipSignature(tt.ownershipSignature, tt.txHash, tt.ownerPublicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateOwnershipSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateOwnershipSignatureErrors(t *testing.T) {
	privKey, _ := btcec.NewPrivateKey()
	pubKey := privKey.PubKey()
	messageHash := sha256.Sum256([]byte("test message"))
	validSig, _ := schnorr.Sign(privKey, messageHash[:])

	tests := []struct {
		name               string
		ownershipSignature []byte
		txHash             []byte
		ownerPublicKey     []byte
		wantErr            string
	}{
		{
			name:               "nil signature",
			ownershipSignature: nil,
			txHash:             messageHash[:],
			ownerPublicKey:     pubKey.SerializeCompressed(),
			wantErr:            "ownership signature cannot be nil",
		},
		{
			name:               "nil transaction hash",
			ownershipSignature: validSig.Serialize(),
			txHash:             nil,
			ownerPublicKey:     pubKey.SerializeCompressed(),
			wantErr:            "hash to verify cannot be nil",
		},
		{
			name:               "nil owner public key",
			ownershipSignature: validSig.Serialize(),
			txHash:             messageHash[:],
			ownerPublicKey:     nil,
			wantErr:            "owner public key cannot be nil",
		},
		{
			name:               "invalid Schnorr signature",
			ownershipSignature: bytes.Repeat([]byte("1"), 64),
			txHash:             messageHash[:],
			ownerPublicKey:     pubKey.SerializeCompressed(),
			wantErr:            "failed to parse signature as either Schnorr or DER",
		},
		{
			name:               "too short Schnorr signature",
			ownershipSignature: []byte{0x01, 0x02, 0x03}, // Too short for a valid Schnorr signature
			txHash:             messageHash[:],
			ownerPublicKey:     pubKey.SerializeCompressed(),
			wantErr:            "malformed signature: too short",
		},
		{
			name:               "invalid ECDSA DER signature",
			ownershipSignature: []byte{0x30, 0x01, 0x02}, // Invalid DER format
			txHash:             messageHash[:],
			ownerPublicKey:     pubKey.SerializeCompressed(),
			wantErr:            "failed to parse signature as either Schnorr or DER",
		},
		{
			name:               "valid Schnorr with different tx hash falls through to ECDSA and fails",
			ownershipSignature: validSig.Serialize(),
			txHash:             []byte("different message hash"), // Different message hash will cause verification to fail
			ownerPublicKey:     pubKey.SerializeCompressed(),
			wantErr:            "failed to parse signature as either Schnorr or DER",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateOwnershipSignature(tt.ownershipSignature, tt.txHash, tt.ownerPublicKey); err == nil {
				t.Errorf("ValidateOwnershipSignature() expected error %v, got nil", tt.wantErr)
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ValidateOwnershipSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsNetworkSupported(t *testing.T) {
	tests := []struct {
		name              string
		providedNetwork   common.Network
		supportedNetworks []common.Network
		want              bool
	}{
		{
			name:              "unspecified network",
			providedNetwork:   common.Unspecified,
			supportedNetworks: []common.Network{common.Mainnet, common.Testnet},
			want:              false,
		},
		{
			name:              "mainnet in list",
			providedNetwork:   common.Mainnet,
			supportedNetworks: []common.Network{common.Mainnet, common.Testnet},
			want:              true,
		},
		{
			name:              "testnet in list",
			providedNetwork:   common.Testnet,
			supportedNetworks: []common.Network{common.Mainnet, common.Testnet},
			want:              true,
		},
		{
			name:              "regtest in list",
			providedNetwork:   common.Regtest,
			supportedNetworks: []common.Network{common.Regtest},
			want:              true,
		},
		{
			name:              "network not in list",
			providedNetwork:   common.Signet,
			supportedNetworks: []common.Network{common.Mainnet, common.Testnet},
			want:              false,
		},
		{
			name:              "empty supported list",
			providedNetwork:   common.Mainnet,
			supportedNetworks: []common.Network{},
			want:              false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isNetworkSupported(tt.providedNetwork, tt.supportedNetworks)
			if got != tt.want {
				t.Errorf("isNetworkSupported(%v, %v) = %v, want %v", tt.providedNetwork, tt.supportedNetworks, got, tt.want)
			}
		})
	}
}

func TestValidateRevocationKeys(t *testing.T) {
	t.Parallel()
	privKey1 := keys.MustGeneratePrivateKeyFromRand(seededRng)
	privKey2 := keys.MustGeneratePrivateKeyFromRand(seededRng)
	privateKeys := []keys.Private{privKey1, privKey2}
	publicKeys := []keys.Public{privKey1.Public(), privKey2.Public()}

	require.NoError(t, ValidateRevocationKeys(privateKeys, publicKeys))
}

func TestValidateRevocationKeysErrors(t *testing.T) {
	t.Parallel()
	privKey1 := keys.MustGeneratePrivateKeyFromRand(seededRng)
	privKey2 := keys.MustGeneratePrivateKeyFromRand(seededRng)
	// Generate a mismatched key pair
	wrongPrivKey := keys.MustGeneratePrivateKeyFromRand(seededRng)
	wrongPubKey := wrongPrivKey.Public()

	tests := []struct {
		name               string
		privateKeys        []keys.Private
		expectedPublicKeys []keys.Public
		errMsg             string
	}{
		{
			name:               "nil private keys",
			privateKeys:        nil,
			expectedPublicKeys: []keys.Public{privKey1.Public()},
			errMsg:             "revocation private keys cannot be nil",
		},
		{
			name:               "nil expected public keys",
			privateKeys:        []keys.Private{privKey1},
			expectedPublicKeys: nil,
			errMsg:             "expected revocation public keys cannot be nil",
		},
		{
			name:               "mismatched lengths",
			privateKeys:        []keys.Private{privKey1},
			expectedPublicKeys: []keys.Public{privKey1.Public(), privKey2.Public()},
			errMsg:             "number of revocation private keys (1) does not match number of expected public keys (2)",
		},
		{
			name:               "nil private key at index",
			privateKeys:        []keys.Private{privKey1, {}},
			expectedPublicKeys: []keys.Public{privKey1.Public(), privKey2.Public()},
			errMsg:             "revocation private key at index 1 cannot be empty",
		},
		{
			name:               "nil expected public key at index",
			privateKeys:        []keys.Private{privKey1, privKey2},
			expectedPublicKeys: []keys.Public{privKey1.Public(), {}},
			errMsg:             "expected revocation public key at index 1 cannot be empty",
		},
		{
			name:               "key mismatch",
			privateKeys:        []keys.Private{privKey1, privKey2},
			expectedPublicKeys: []keys.Public{privKey1.Public(), wrongPubKey},
			errMsg:             "revocation key mismatch at index 1: derived public key does not match expected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.ErrorContains(t, ValidateRevocationKeys(tt.privateKeys, tt.expectedPublicKeys), tt.errMsg)
		})
	}
}

func TestHashFreezeTokensPayloadErrors(t *testing.T) {
	t.Parallel()

	ownerPrivKey, _ := keys.GeneratePrivateKey()
	ownerPubKey := ownerPrivKey.Public()
	tokenPrivKey, _ := keys.GeneratePrivateKey()
	tokenPubKey := tokenPrivKey.Public()
	operatorPrivKey, _ := keys.GeneratePrivateKey()
	operatorPubKey := operatorPrivKey.Public()
	tokenIdentifier := make([]byte, 32)
	copy(tokenIdentifier, "test_token_identifier_32bytes___")

	tests := []struct {
		name    string
		payload *tokenpb.FreezeTokensPayload
		wantErr string
	}{
		{
			name:    "nil payload",
			payload: nil,
			wantErr: "freeze tokens payload cannot be nil",
		},
		{
			name: "empty owner public key v0",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   0,
				OwnerPublicKey:            []byte{},
				TokenPublicKey:            tokenPubKey.Serialize(),
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			wantErr: "owner public key cannot be empty",
		},
		{
			name: "empty token public key v0",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   0,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenPublicKey:            []byte{},
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			wantErr: "token public key cannot be empty",
		},
		{
			name: "zero timestamp v0",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   0,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenPublicKey:            tokenPubKey.Serialize(),
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   0,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			wantErr: "issuer provided timestamp cannot be 0",
		},
		{
			name: "empty operator public key v0",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   0,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenPublicKey:            tokenPubKey.Serialize(),
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: []byte{},
			},
			wantErr: "operator identity public key cannot be empty",
		},
		{
			name: "empty owner public key v1",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   1,
				OwnerPublicKey:            []byte{},
				TokenIdentifier:           tokenIdentifier,
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			wantErr: "owner public key cannot be empty",
		},
		{
			name: "missing token identifier v1",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   1,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			wantErr: "token identifier cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := HashFreezeTokensPayload(tt.payload)
			if err == nil {
				t.Errorf("HashFreezeTokensPayload() expected error %v, got nil", tt.wantErr)
				return
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("HashFreezeTokensPayload() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestHashFreezeTokensPayloadParameterChanges(t *testing.T) {
	t.Parallel()
	ownerPrivKey, _ := keys.GeneratePrivateKey()
	ownerPubKey := ownerPrivKey.Public()
	tokenPrivKey, _ := keys.GeneratePrivateKey()
	tokenPubKey := tokenPrivKey.Public()
	operatorPrivKey, _ := keys.GeneratePrivateKey()
	operatorPubKey := operatorPrivKey.Public()
	tokenIdentifier := make([]byte, 32)
	copy(tokenIdentifier, "test_token_identifier_32bytes___")

	ownerPrivKey2, _ := keys.GeneratePrivateKey()
	ownerPubKey2 := ownerPrivKey2.Public()
	tokenPrivKey2, _ := keys.GeneratePrivateKey()
	tokenPubKey2 := tokenPrivKey2.Public()
	operatorPrivKey2, _ := keys.GeneratePrivateKey()
	operatorPubKey2 := operatorPrivKey2.Public()
	tokenIdentifier2 := make([]byte, 32)
	copy(tokenIdentifier2, "different_token_id_32bytes______")

	// Test version 0 base payload with valid values
	basePayloadV0 := &tokenpb.FreezeTokensPayload{
		Version:                   0,
		OwnerPublicKey:            ownerPubKey.Serialize(),
		TokenPublicKey:            tokenPubKey.Serialize(),
		ShouldUnfreeze:            false,
		IssuerProvidedTimestamp:   1234567890,
		OperatorIdentityPublicKey: operatorPubKey.Serialize(),
	}
	baseHashV0, _ := HashFreezeTokensPayload(basePayloadV0)

	// Test version 1 base payload with valid values
	basePayloadV1 := &tokenpb.FreezeTokensPayload{
		Version:                   1,
		OwnerPublicKey:            ownerPubKey.Serialize(),
		TokenIdentifier:           tokenIdentifier,
		ShouldUnfreeze:            false,
		IssuerProvidedTimestamp:   1234567890,
		OperatorIdentityPublicKey: operatorPubKey.Serialize(),
	}
	baseHashV1, _ := HashFreezeTokensPayload(basePayloadV1)

	// Ensure v0 and v1 produce different hashes
	if bytes.Equal(baseHashV0, baseHashV1) {
		t.Fatal("Version 0 and version 1 should produce different hashes")
	}

	tests := []struct {
		name     string
		payload  *tokenpb.FreezeTokensPayload
		baseHash []byte
	}{
		// Version 0 tests
		{
			name: "v0 different owner public key",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   0,
				OwnerPublicKey:            ownerPubKey2.Serialize(),
				TokenPublicKey:            tokenPubKey.Serialize(),
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			baseHash: baseHashV0,
		},
		{
			name: "v0 different token public key",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   0,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenPublicKey:            tokenPubKey2.Serialize(),
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			baseHash: baseHashV0,
		},
		{
			name: "v0 different shouldUnfreeze",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   0,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenPublicKey:            tokenPubKey.Serialize(),
				ShouldUnfreeze:            true,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			baseHash: baseHashV0,
		},
		{
			name: "v0 different timestamp",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   0,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenPublicKey:            tokenPubKey.Serialize(),
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   9876543210,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			baseHash: baseHashV0,
		},
		{
			name: "v0 different operator public key",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   0,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenPublicKey:            tokenPubKey.Serialize(),
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey2.Serialize(),
			},
			baseHash: baseHashV0,
		},
		// Version 1 tests
		{
			name: "v1 different owner public key",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   1,
				OwnerPublicKey:            ownerPubKey2.Serialize(),
				TokenIdentifier:           tokenIdentifier,
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			baseHash: baseHashV1,
		},
		{
			name: "v1 different token identifier",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   1,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenIdentifier:           tokenIdentifier2,
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			baseHash: baseHashV1,
		},
		{
			name: "v1 different shouldUnfreeze",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   1,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenIdentifier:           tokenIdentifier,
				ShouldUnfreeze:            true,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			baseHash: baseHashV1,
		},
		{
			name: "v1 different timestamp",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   1,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenIdentifier:           tokenIdentifier,
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   9876543210,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			baseHash: baseHashV1,
		},
		{
			name: "v1 different operator public key",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   1,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenIdentifier:           tokenIdentifier,
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey2.Serialize(),
			},
			baseHash: baseHashV1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			hash, err := HashFreezeTokensPayload(tt.payload)
			if err != nil {
				t.Fatalf("HashFreezeTokensPayload() error = %v", err)
			}
			if len(hash) != 32 {
				t.Errorf("HashFreezeTokensPayload() hash length = %v, want 32", len(hash))
			}
			if bytes.Equal(hash, tt.baseHash) {
				t.Fatalf("HashFreezeTokensPayload() produced same hash as base for %s", tt.name)
			}
		})
	}
}

func TestValidateFreezeTokensPayload(t *testing.T) {
	t.Parallel()

	ownerPrivKey, _ := keys.GeneratePrivateKey()
	ownerPubKey := ownerPrivKey.Public()
	tokenPrivKey, _ := keys.GeneratePrivateKey()
	tokenPubKey := tokenPrivKey.Public()
	operatorPrivKey, _ := keys.GeneratePrivateKey()
	operatorPubKey := operatorPrivKey.Public()
	tokenIdentifier := make([]byte, 32)
	copy(tokenIdentifier, "test_token_identifier_32bytes___")

	validPayloadV0 := &tokenpb.FreezeTokensPayload{
		Version:                   0,
		OwnerPublicKey:            ownerPubKey.Serialize(),
		TokenPublicKey:            tokenPubKey.Serialize(),
		ShouldUnfreeze:            false,
		IssuerProvidedTimestamp:   1234567890,
		OperatorIdentityPublicKey: operatorPubKey.Serialize(),
	}

	validPayloadV1 := &tokenpb.FreezeTokensPayload{
		Version:                   1,
		OwnerPublicKey:            ownerPubKey.Serialize(),
		TokenIdentifier:           tokenIdentifier,
		ShouldUnfreeze:            false,
		IssuerProvidedTimestamp:   1234567890,
		OperatorIdentityPublicKey: operatorPubKey.Serialize(),
	}

	tests := []struct {
		name            string
		payload         *tokenpb.FreezeTokensPayload
		wantOperatorKey keys.Public
		wantErr         string
	}{
		{
			name:            "nil payload",
			payload:         nil,
			wantOperatorKey: operatorPubKey,
			wantErr:         "freeze tokens payload cannot be nil",
		},
		{
			name: "invalid version",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   2,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenPublicKey:            tokenPubKey.Serialize(),
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			wantOperatorKey: operatorPubKey,
			wantErr:         "invalid freeze tokens payload version: 2",
		},
		{
			name: "v0 empty owner public key",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   0,
				OwnerPublicKey:            []byte{},
				TokenPublicKey:            tokenPubKey.Serialize(),
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			wantOperatorKey: operatorPubKey,
			wantErr:         "owner public key cannot be empty",
		},
		{
			name: "v0 nil token public key",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   0,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			wantOperatorKey: operatorPubKey,
			wantErr:         "token public key cannot be nil for version 0",
		},
		{
			name: "v0 with token identifier (should fail)",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   0,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenPublicKey:            tokenPubKey.Serialize(),
				TokenIdentifier:           tokenIdentifier,
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			wantOperatorKey: operatorPubKey,
			wantErr:         "token identifier must be nil for version 0",
		},
		{
			name: "v1 nil token identifier",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   1,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			wantOperatorKey: operatorPubKey,
			wantErr:         "token identifier must be exactly 32 bytes, got 0",
		},
		{
			name: "v1 with token public key (should fail)",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   1,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenPublicKey:            tokenPubKey.Serialize(),
				TokenIdentifier:           tokenIdentifier,
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			wantOperatorKey: operatorPubKey,
			wantErr:         "token public key must be nil for version 1",
		},
		{
			name: "v1 wrong token identifier length",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   1,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenIdentifier:           []byte("short"),
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			wantOperatorKey: operatorPubKey,
			wantErr:         "token identifier must be exactly 32 bytes, got 5",
		},
		{
			name: "zero timestamp",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   0,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenPublicKey:            tokenPubKey.Serialize(),
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   0,
				OperatorIdentityPublicKey: operatorPubKey.Serialize(),
			},
			wantOperatorKey: operatorPubKey,
			wantErr:         "issuer provided timestamp cannot be 0",
		},
		{
			name: "empty operator public key",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   0,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenPublicKey:            tokenPubKey.Serialize(),
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: []byte{},
			},
			wantOperatorKey: operatorPubKey,
			wantErr:         "failed to parse operator identity public key",
		},
		{
			name: "operator public key not in config",
			payload: &tokenpb.FreezeTokensPayload{
				Version:                   0,
				OwnerPublicKey:            ownerPubKey.Serialize(),
				TokenPublicKey:            tokenPubKey.Serialize(),
				ShouldUnfreeze:            false,
				IssuerProvidedTimestamp:   1234567890,
				OperatorIdentityPublicKey: []byte{0x03, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22},
			},
			wantOperatorKey: operatorPubKey, // Different from the payload's operator key
			wantErr:         "does not match expected operator",
		},
		{
			name:            "valid v0 payload with matching operator",
			payload:         validPayloadV0,
			wantOperatorKey: operatorPubKey,
			wantErr:         "",
		},
		{
			name:            "valid v1 payload with matching operator",
			payload:         validPayloadV1,
			wantOperatorKey: operatorPubKey,
			wantErr:         "",
		},
		{
			name:            "valid payload with nil expected operator (should fail)",
			payload:         validPayloadV0,
			wantOperatorKey: keys.Public{},
			wantErr:         "does not match expected operator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateFreezeTokensPayload(tt.payload, tt.wantOperatorKey)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

func TestHashFreezeTokensPayloadVersionConsistency(t *testing.T) {
	t.Parallel()

	ownerPrivKey, _ := keys.GeneratePrivateKey()
	ownerPubKey := ownerPrivKey.Public()
	tokenPrivKey, _ := keys.GeneratePrivateKey()
	tokenPubKey := tokenPrivKey.Public()
	operatorPrivKey, _ := keys.GeneratePrivateKey()
	operatorPubKey := operatorPrivKey.Public()
	tokenIdentifier := make([]byte, 32)
	copy(tokenIdentifier, "test_token_identifier_32bytes___")

	// Create a v0 payload
	payloadV0 := &tokenpb.FreezeTokensPayload{
		Version:                   0,
		OwnerPublicKey:            ownerPubKey.Serialize(),
		TokenPublicKey:            tokenPubKey.Serialize(),
		ShouldUnfreeze:            false,
		IssuerProvidedTimestamp:   1234567890,
		OperatorIdentityPublicKey: operatorPubKey.Serialize(),
	}

	// Create a v1 payload
	payloadV1 := &tokenpb.FreezeTokensPayload{
		Version:                   1,
		OwnerPublicKey:            ownerPubKey.Serialize(),
		TokenIdentifier:           tokenIdentifier,
		ShouldUnfreeze:            false,
		IssuerProvidedTimestamp:   1234567890,
		OperatorIdentityPublicKey: operatorPubKey.Serialize(),
	}

	hashV0, err := HashFreezeTokensPayload(payloadV0)
	if err != nil {
		t.Fatalf("HashFreezeTokensPayload() v0 error = %v", err)
	}

	hashV1, err := HashFreezeTokensPayload(payloadV1)
	if err != nil {
		t.Fatalf("HashFreezeTokensPayload() v1 error = %v", err)
	}

	// Verify different versions produce different hashes
	if bytes.Equal(hashV0, hashV1) {
		t.Error("Version 0 and version 1 payloads should produce different hashes")
	}

	// Verify hash consistency - same input should always produce same hash
	hashV0Again, err := HashFreezeTokensPayload(payloadV0)
	if err != nil {
		t.Fatalf("HashFreezeTokensPayload() v0 second hash error = %v", err)
	}

	if !bytes.Equal(hashV0, hashV0Again) {
		t.Error("Version 0 payload should produce consistent hashes")
	}

	hashV1Again, err := HashFreezeTokensPayload(payloadV1)
	if err != nil {
		t.Fatalf("HashFreezeTokensPayload() v1 second hash error = %v", err)
	}

	if !bytes.Equal(hashV1, hashV1Again) {
		t.Error("Version 1 payload should produce consistent hashes")
	}
}
