package common

import (
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	pb "github.com/lightsparkdev/spark/proto/spark"
)

func TestEncodeDecodeSparkInvoice(t *testing.T) {
	testCases := []struct {
		name                   string
		emptyAmount            bool
		emptyMemo              bool
		emptyExpiryTime        bool
		emptySenderPublicKey   bool
		emptyId                bool
		emptyIdentityPublicKey bool
		emptyTokenIdentifier   bool
		overMaxSatsAmount      bool
		invalidPaymentType     bool
		invalidVersion         bool
		invalidId              bool
	}{
		{
			name: "no empty fields",
		},
		{
			name:        "empty amount",
			emptyAmount: true,
		},
		{
			name:      "empty memo",
			emptyMemo: true,
		},
		{
			name:            "empty expiry time",
			emptyExpiryTime: true,
		},
		{
			name:                 "empty sender public key",
			emptySenderPublicKey: true,
		},
		{
			name:    "empty id",
			emptyId: true,
		},
		{
			name:                   "empty identity public key",
			emptyIdentityPublicKey: true,
		},
		{
			name:                 "empty token identifier",
			emptyTokenIdentifier: true,
		},
		{
			name:              "over max sats amount",
			overMaxSatsAmount: true,
		},
		{
			name:               "invalid payment type",
			invalidPaymentType: true,
		},
		{
			name:           "invalid version",
			invalidVersion: true,
		},
		{
			name:      "invalid id",
			invalidId: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			identityPublicKey, err := hex.DecodeString("02ccb26ba79c63aaf60c9192fd874be3087ae8d8703275df0e558704a6d3a4f132")
			require.NoError(t, err)
			senderPublicKey := make([]byte, len(identityPublicKey))
			copy(senderPublicKey, identityPublicKey)

			testUUID, err := uuid.NewV7()
			if err != nil {
				t.Fatalf("failed to generate uuid: %v", err)
			}
			tokenIdentifier, err := hex.DecodeString("9cef64327b1c1f18eb4b4944fc70a1fe9dd84d9084c7daae751de535baafd49f")
			if err != nil {
				t.Fatalf("failed to decode token identifier: %v", err)
			}
			var amount uint64 = 1000
			satsAmount := &amount
			tokenAmount := big.NewInt(1000).Bytes()
			expiryTime := time.Now().Add(24 * time.Hour).UTC()
			memo := "myMemo"

			if tc.emptyMemo {
				memo = ""
			}
			if tc.emptyExpiryTime {
				expiryTime = time.Time{}
			}
			if tc.emptySenderPublicKey {
				senderPublicKey = nil
			}
			if tc.emptyIdentityPublicKey {
				identityPublicKey = nil
			}
			if tc.emptyAmount {
				tokenAmount = nil
				satsAmount = nil
			}
			if tc.overMaxSatsAmount {
				satsAmount = new(uint64)
				*satsAmount = 2_100_000_000_000_001
			}
			if tc.emptyTokenIdentifier {
				tokenIdentifier = nil
			}

			tokenInvoiceFields := CreateTokenSparkInvoiceFields(
				testUUID[:],
				tokenIdentifier,
				tokenAmount,
				&memo,
				senderPublicKey,
				&expiryTime,
			)
			satsInvoiceFields := CreateSatsSparkInvoiceFields(
				testUUID[:],
				satsAmount,
				&memo,
				senderPublicKey,
				&expiryTime,
			)

			if tc.invalidVersion {
				tokenInvoiceFields.Version = 9999
				satsInvoiceFields.Version = 9999
			}
			if tc.invalidId {
				tokenInvoiceFields.Id = []byte{1, 2, 3}
				satsInvoiceFields.Id = []byte{1, 2, 3}
			}
			if tc.invalidPaymentType {
				tokenInvoiceFields.PaymentType = nil
				satsInvoiceFields.PaymentType = nil
			}

			tokensInvoice, err := EncodeSparkAddress(identityPublicKey, Regtest, tokenInvoiceFields)
			if tc.invalidPaymentType || tc.invalidVersion || tc.invalidId || tc.emptyIdentityPublicKey {
				require.Error(t, err, "expected error")
			} else {
				require.NoError(t, err, "failed to encode spark address")
			}

			satsInvoice, err := EncodeSparkAddress(identityPublicKey, Regtest, satsInvoiceFields)
			if tc.invalidPaymentType || tc.invalidVersion || tc.invalidId || tc.emptyIdentityPublicKey || tc.overMaxSatsAmount {
				require.Error(t, err, "expected error")
				return // Early return to avoid decoding the invalid invoices
			} else {
				require.NoError(t, err, "failed to encode spark address")
			}

			decodedTokensInvoice, err := DecodeSparkAddress(tokensInvoice)
			require.NoError(t, err, "failed to decode spark address")

			decodedSatsInvoice, err := DecodeSparkAddress(satsInvoice)
			require.NoError(t, err, "failed to decode spark address")

			require.Equal(t, Regtest, decodedTokensInvoice.Network, "network does not match")
			require.Equal(t, identityPublicKey, decodedTokensInvoice.SparkAddress.IdentityPublicKey, "identity public key does not match")
			require.Equal(t, testUUID[:], decodedTokensInvoice.SparkAddress.SparkInvoiceFields.Id, "id does not match")
			require.Equal(t, memo, *decodedTokensInvoice.SparkAddress.SparkInvoiceFields.Memo, "memo does not match")
			require.Equal(t, senderPublicKey, decodedTokensInvoice.SparkAddress.SparkInvoiceFields.SenderPublicKey, "sender public key does not match")
			require.Equal(t, expiryTime, decodedTokensInvoice.SparkAddress.SparkInvoiceFields.ExpiryTime.AsTime(), "expiry time does not match")
			require.Equal(t, tokenIdentifier, decodedTokensInvoice.SparkAddress.SparkInvoiceFields.PaymentType.(*pb.SparkInvoiceFields_TokensPayment).TokensPayment.TokenIdentifier, "token identifier does not match")
			require.Equal(t, tokenAmount, decodedTokensInvoice.SparkAddress.SparkInvoiceFields.PaymentType.(*pb.SparkInvoiceFields_TokensPayment).TokensPayment.Amount, "amount does not match")

			require.NoError(t, err, "failed to decode spark address")
			require.Equal(t, Regtest, decodedSatsInvoice.Network, "network does not match")
			require.Equal(t, identityPublicKey, decodedSatsInvoice.SparkAddress.IdentityPublicKey, "identity public key does not match")
			require.Equal(t, testUUID[:], decodedSatsInvoice.SparkAddress.SparkInvoiceFields.Id, "id does not match")
			require.Equal(t, memo, *decodedSatsInvoice.SparkAddress.SparkInvoiceFields.Memo, "memo does not match")
			require.Equal(t, senderPublicKey, decodedSatsInvoice.SparkAddress.SparkInvoiceFields.SenderPublicKey, "sender public key does not match")
			require.Equal(t, expiryTime, decodedSatsInvoice.SparkAddress.SparkInvoiceFields.ExpiryTime.AsTime(), "expiry time does not match")
			require.Equal(t, satsAmount, decodedSatsInvoice.SparkAddress.SparkInvoiceFields.PaymentType.(*pb.SparkInvoiceFields_SatsPayment).SatsPayment.Amount, "amount does not match")
		})
	}
}

func TestDecodeKnownTokensSparkInvoice(t *testing.T) {
	tokensAddress := "sprt1pgss9n9jdwnecca27cxfryhasa97xzr6arv8qvn4mu89tpcy5mf6fufjzfnssqgjzqqes6qh0dhh4duxm3x8083hwjkp5fs2yzww7epj0vwp7x8tfdy5flrs58lfmkzdjzzv0k4ww5w72dd64l2f7yszq05z5pnd09xk2mt0xgss9n9jdwnecca27cxfryhasa97xzr6arv8qvn4mu89tpcy5mf6fufjcfxyx0"

	res, err := DecodeSparkAddress(tokensAddress)
	require.NoError(t, err, "failed to decode tokens address")

	expectedIdentityPubKey, _ := hex.DecodeString("02ccb26ba79c63aaf60c9192fd874be3087ae8d8703275df0e558704a6d3a4f132")
	require.Equal(t, expectedIdentityPubKey, res.SparkAddress.IdentityPublicKey, "identity public key does not match for tokens address")

	tokensPayment, ok := res.SparkAddress.SparkInvoiceFields.PaymentType.(*pb.SparkInvoiceFields_TokensPayment)
	require.True(t, ok, "expected tokens payment, got: %T", res.SparkAddress.SparkInvoiceFields.PaymentType)

	require.Equal(t, uint32(1), res.SparkAddress.SparkInvoiceFields.Version, "version does not match")
	require.NotNil(t, res.SparkAddress.SparkInvoiceFields.Id, "id should not be nil")

	expectedId, _ := hex.DecodeString("019868177b6f7ab786dc4c779e3774ac")
	require.Equal(t, expectedId, res.SparkAddress.SparkInvoiceFields.Id, "id does not match")

	expectedTokenId, _ := hex.DecodeString("9cef64327b1c1f18eb4b4944fc70a1fe9dd84d9084c7daae751de535baafd49f")
	require.Equal(t, expectedTokenId, tokensPayment.TokensPayment.TokenIdentifier, "token identifier does not match")

	amount := tokensPayment.TokensPayment.Amount
	expectedAmount := big.NewInt(1000).Bytes()
	require.Equal(t, expectedAmount, amount, "amount does not match")

	require.NotNil(t, res.SparkAddress.SparkInvoiceFields.Memo, "memo should not be nil")
	require.Equal(t, "myMemo", *res.SparkAddress.SparkInvoiceFields.Memo, "memo does not match")

	require.Nil(t, res.SparkAddress.SparkInvoiceFields.ExpiryTime, "expiry time should be nil")

	require.NotNil(t, res.SparkAddress.SparkInvoiceFields.SenderPublicKey, "sender public key should not be nil")
	require.Equal(t, expectedIdentityPubKey, res.SparkAddress.SparkInvoiceFields.SenderPublicKey, "sender public key does not match")
}

func TestDecodeKnownSatsSparkInvoice(t *testing.T) {
	satsAddress := "sprt1pgss9n9jdwnecca27cxfryhasa97xzr6arv8qvn4mu89tpcy5mf6fufjzffqsqgjzqqe3qgg3u7hnmdqfft7ash9vrfjyqcgaqrj5pnd09xk2mt0xgss9n9jdwnecca27cxfryhasa97xzr6arv8qvn4mu89tpcy5mf6fufj8gxq3a5n6nzqvyxqmtkesqskz5jyy"

	res, err := DecodeSparkAddress(satsAddress)
	require.NoError(t, err, "failed to decode sats address")

	expectedIdentityPubKey, _ := hex.DecodeString("02ccb26ba79c63aaf60c9192fd874be3087ae8d8703275df0e558704a6d3a4f132")
	require.Equal(t, expectedIdentityPubKey, res.SparkAddress.IdentityPublicKey, "identity public key does not match for sats address")

	satsPayment, ok := res.SparkAddress.SparkInvoiceFields.PaymentType.(*pb.SparkInvoiceFields_SatsPayment)
	require.True(t, ok, "expected sats payment, got: %T", res.SparkAddress.SparkInvoiceFields.PaymentType)
	require.Equal(t, uint32(1), res.SparkAddress.SparkInvoiceFields.Version, "version does not match")

	require.NotNil(t, res.SparkAddress.SparkInvoiceFields.Id, "id should not be nil")
	expectedId, _ := hex.DecodeString("019881088f3d79eda04a57eec2e560d3")
	require.Equal(t, expectedId, res.SparkAddress.SparkInvoiceFields.Id, "id does not match")

	require.Equal(t, uint64(1000), *satsPayment.SatsPayment.Amount, "sats amount does not match")

	require.NotNil(t, res.SparkAddress.SparkInvoiceFields.ExpiryTime, "expiry time should not be nil")
	expectedExpiryTime := time.Date(2025, 8, 7, 20, 17, 58, 589000000, time.UTC)
	require.Equal(t, expectedExpiryTime, res.SparkAddress.SparkInvoiceFields.ExpiryTime.AsTime(), "expiry time does not match")

	require.NotNil(t, res.SparkAddress.SparkInvoiceFields.Memo, "memo should not be nil")
	require.Equal(t, "myMemo", *res.SparkAddress.SparkInvoiceFields.Memo, "memo does not match")

	require.NotNil(t, res.SparkAddress.SparkInvoiceFields.SenderPublicKey, "sender public key should not be nil")
	require.Equal(t, expectedIdentityPubKey, res.SparkAddress.SparkInvoiceFields.SenderPublicKey, "sender public key does not match")
}
