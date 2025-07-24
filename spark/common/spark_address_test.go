package common

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/google/uuid"

	pb "github.com/lightsparkdev/spark/proto/spark"
)

func TestEncodeDecodeSparkAddressMaxUint128(t *testing.T) {
	identityPublicKey, err := hex.DecodeString("02cb3ce66d5380404bcad625ebda345997ee300c7d17501853a210bff005a7ca82")
	if err != nil {
		t.Fatalf("failed to decode hex string: %v", err)
	}
	testUUID, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("failed to generate uuid: %v", err)
	}
	memo := "test"
	paymentIntentFields := pb.PaymentIntentFields{
		Id:              testUUID[:],
		AssetIdentifier: []byte{},
		AssetAmount: []byte{
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
		},
		Memo: &memo,
	}
	sparkAddress, err := EncodeSparkAddress(identityPublicKey, Regtest, &paymentIntentFields)
	if err != nil {
		t.Fatalf("failed to encode spark address: %v", err)
	}
	res, err := DecodeSparkAddress(sparkAddress)
	if err != nil {
		t.Fatalf("failed to decode spark address: %v", err)
	}
	if !bytes.Equal(identityPublicKey, res.SparkAddress.IdentityPublicKey) {
		t.Fatalf("identity public key does not match")
	}
	if res.Network != Regtest {
		t.Fatalf("network does not match")
	}
	if !bytes.Equal(testUUID[:], res.SparkAddress.PaymentIntentFields.Id) {
		t.Fatalf("id does not match")
	}
	if !bytes.Equal([]byte{}, res.SparkAddress.PaymentIntentFields.AssetIdentifier) {
		t.Fatalf("asset identifier does not match")
	}
	if res.SparkAddress.PaymentIntentFields.Memo == nil || *res.SparkAddress.PaymentIntentFields.Memo != memo {
		t.Fatalf("memo does not match: %v != %v", *res.SparkAddress.PaymentIntentFields.Memo, memo)
	}
	if !bytes.Equal(res.SparkAddress.PaymentIntentFields.AssetAmount, []byte{
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
	}) {
		t.Fatalf("asset amount does not match")
	}
}

func TestDecodeSparkAddress(t *testing.T) {
	res, err := DecodeSparkAddress("sprt1pgss9jeuuek48qzqf09dvf0tmg69n9lwxqx8696srpf6yy9l7qz60j5zzfrs5yqpja46zyyjwgmffm38lgzu9ue2zgss9jeuuek48qzqf09dvf0tmg69n9lwxqx8696srpf6yy9l7qz60j5zrgp39458yg9hgetnw3kk2mt0xyerx3gd5s0")
	if err != nil {
		t.Fatalf("failed to decode spark address: %v", err)
	}

	identityPublicKey := res.SparkAddress.IdentityPublicKey
	expectedBytes, err := hex.DecodeString("02cb3ce66d5380404bcad625ebda345997ee300c7d17501853a210bff005a7ca82")
	if err != nil {
		fmt.Println("Error decoding hex string:", err)
		return
	}
	if !bytes.Equal(expectedBytes, identityPublicKey) {
		t.Fatalf("identity public key does not match")
	}
	network := res.Network
	if network != Regtest {
		t.Fatalf("network does not match")
	}
	id := res.SparkAddress.PaymentIntentFields.Id
	expectedID := []byte{1, 151, 107, 161, 16, 146, 114, 54, 148, 238, 39, 250, 5, 194, 243, 42}
	if !bytes.Equal(expectedID, id) {
		t.Fatalf("id does not match: %v != %v", expectedID, id)
	}
	assetIdentifier := res.SparkAddress.PaymentIntentFields.AssetIdentifier
	if !bytes.Equal(assetIdentifier, expectedBytes) {
		t.Fatalf("asset identifier does not match")
	}
	memo := res.SparkAddress.PaymentIntentFields.Memo
	if memo == nil || *memo != "testmemo123" {
		t.Fatalf("memo does not match: %v != %v", *memo, "testmemo123")
	}
	// amount := res.SparkAddress.PaymentIntentFields.AssetAmount
	amount := res.SparkAddress.PaymentIntentFields.AssetAmount
	largeNumber := new(big.Int)
	largeNumber.SetString("1234567", 10)
	expected := largeNumber.Bytes()
	if !bytes.Equal(expected, amount) {
		t.Fatalf("amount does not match: %v != %v", expected, amount)
	}
}
