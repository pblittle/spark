package common

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/google/uuid"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type DecodedSparkAddress struct {
	SparkAddress *pb.SparkAddress
	Network      Network
}

// CreateTokenSparkInvoiceFields creates SparkInvoiceFields for token payments
func CreateTokenSparkInvoiceFields(id []byte, tokenIdentifier []byte, amount []byte, memo *string, senderPublicKey []byte, expiryTime *time.Time) *pb.SparkInvoiceFields {
	sparkInvoiceFields := &pb.SparkInvoiceFields{
		Version: 1,
		Id:      id,
		PaymentType: &pb.SparkInvoiceFields_TokensPayment{
			TokensPayment: &pb.TokensPayment{
				TokenIdentifier: tokenIdentifier,
				Amount:          amount,
			},
		},
		Memo:            memo,
		SenderPublicKey: senderPublicKey,
	}
	if expiryTime != nil {
		sparkInvoiceFields.ExpiryTime = timestamppb.New(*expiryTime)
	}
	return sparkInvoiceFields
}

// CreateSatsSparkInvoiceFields creates SparkInvoiceFields for sats payments
func CreateSatsSparkInvoiceFields(id []byte, amount *uint64, memo *string, senderPublicKey []byte, expiryTime *time.Time) *pb.SparkInvoiceFields {
	sparkInvoiceFields := &pb.SparkInvoiceFields{
		Version: 1,
		Id:      id,
		PaymentType: &pb.SparkInvoiceFields_SatsPayment{
			SatsPayment: &pb.SatsPayment{
				Amount: amount,
			},
		},
		Memo:            memo,
		SenderPublicKey: senderPublicKey,
	}
	if expiryTime != nil {
		sparkInvoiceFields.ExpiryTime = timestamppb.New(*expiryTime)
	}
	return sparkInvoiceFields
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

func EncodeSparkAddress(identityPublicKey []byte, network Network, sparkInvoiceFields *pb.SparkInvoiceFields) (string, error) {
	if identityPublicKey == nil {
		return "", fmt.Errorf("identity public key is required")
	}
	if sparkInvoiceFields != nil {
		if sparkInvoiceFields.Version != 1 {
			return "", fmt.Errorf("version must be 1")
		}
		if sparkInvoiceFields.Id == nil {
			return "", fmt.Errorf("id is required")
		}
		if _, err := uuid.FromBytes(sparkInvoiceFields.Id); err != nil {
			return "", fmt.Errorf("id is not a valid uuid: %w", err)
		}
		paymentType := sparkInvoiceFields.PaymentType
		switch paymentType.(type) {
		case *pb.SparkInvoiceFields_TokensPayment:
			tokensPayment := paymentType.(*pb.SparkInvoiceFields_TokensPayment).TokensPayment
			if tokensPayment == nil {
				return "", fmt.Errorf("tokens payment is required")
			}
			break
		case *pb.SparkInvoiceFields_SatsPayment:
			satsPayment := paymentType.(*pb.SparkInvoiceFields_SatsPayment).SatsPayment
			const MAX_SATS_AMOUNT = 2_100_000_000_000_000 // 21_000_000 BTC * 100_000_000 sats/BTC
			if satsPayment == nil {
				return "", fmt.Errorf("sats payment is required")
			}
			if satsPayment.Amount != nil && *satsPayment.Amount > MAX_SATS_AMOUNT {
				return "", fmt.Errorf("sats amount must be between 0 and %d", MAX_SATS_AMOUNT)
			}
		default:
			return "", fmt.Errorf("invalid payment type: %T", paymentType)
		}
	}

	sparkAddress := &pb.SparkAddress{
		IdentityPublicKey:  identityPublicKey,
		SparkInvoiceFields: sparkInvoiceFields,
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
