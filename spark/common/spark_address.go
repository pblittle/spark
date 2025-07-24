package common

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil/bech32"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"google.golang.org/protobuf/proto"
)

type DecodedSparkAddress struct {
	SparkAddress *pb.SparkAddress
	Network      Network
}

func DecodeSparkAddress(address string) (*DecodedSparkAddress, error) {
	hrp, data, err := bech32.DecodeNoLimit(address)
	if err != nil {
		return nil, err
	}

	network, err := HrpToNetwork(hrp)
	if err != nil {
		return nil, err
	}

	// Convert 5-bit bech32 data to 8-bit bytes
	byteData, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return nil, err
	}

	sparkAddress := &pb.SparkAddress{}
	if err := proto.Unmarshal(byteData, sparkAddress); err != nil {
		return nil, err
	}

	return &DecodedSparkAddress{
		SparkAddress: sparkAddress,
		Network:      network,
	}, nil
}

func EncodeSparkAddress(identityPublicKey []byte, network Network, paymentIntentFields *pb.PaymentIntentFields) (string, error) {
	sparkAddress := &pb.SparkAddress{
		IdentityPublicKey:   identityPublicKey,
		PaymentIntentFields: paymentIntentFields,
	}
	sparkAddressBytes, err := proto.Marshal(sparkAddress)
	if err != nil {
		return "", err
	}

	// Convert 8-bit bytes to 5-bit bech32 data
	bech32Data, err := bech32.ConvertBits(sparkAddressBytes, 8, 5, true)
	if err != nil {
		return "", err
	}

	hrp, err := NetworkToHrp(network)
	if err != nil {
		return "", err
	}

	data, err := bech32.EncodeM(hrp, bech32Data)
	if err != nil {
		return "", err
	}
	return data, nil
}

func HrpToNetwork(hrp string) (Network, error) {
	switch hrp {
	case "sprt":
		return Regtest, nil
	case "spt":
		return Testnet, nil
	case "sps":
		return Signet, nil
	case "sp":
		return Mainnet, nil
	}
	return Unspecified, nil
}

func NetworkToHrp(network Network) (string, error) {
	switch network {
	case Regtest:
		return "sprt", nil
	case Testnet:
		return "spt", nil
	case Signet:
		return "sps", nil
	case Mainnet:
		return "sp", nil
	default:
		return "", fmt.Errorf("unknown network: %v", network)
	}
}
