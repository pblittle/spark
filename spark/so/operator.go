package so

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/lightsparkdev/spark/common/keys"

	"github.com/lightsparkdev/spark/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so/utils"
	"google.golang.org/grpc"
)

// SigningOperator is the information about a signing operator.
type SigningOperator struct {
	// ID is the index of the signing operator.
	ID uint64
	// Identifier is the identifier of the signing operator, which will be index + 1 in 32 bytes big endian hex string.
	// Used as shamir secret share identifier in DKG key shares.
	Identifier string
	// AddressRpc is the address of the signing operator.
	AddressRpc string
	// Address is the address of the signing operator used for serving the DKG service.
	AddressDkg string
	// IdentityPublicKey is the identity public key of the signing operator.
	IdentityPublicKey keys.Public
	// ServerCertPath is the path to the server certificate.
	CertPath *string
	// ExternalAddress is the external address of the signing operator.
	ExternalAddress string
}

// jsonSigningOperator is used for JSON unmarshaling
type jsonSigningOperator struct {
	ID                uint32  `json:"id"`
	Address           string  `json:"address"`
	AddressDkg        *string `json:"address_dkg"`
	IdentityPublicKey string  `json:"identity_public_key"`
	CertPath          *string `json:"cert_path"`
	ExternalAddress   string  `json:"external_address"`
}

// UnmarshalJSON implements json.Unmarshaler interface
func (s *SigningOperator) UnmarshalJSON(data []byte) error {
	var js jsonSigningOperator
	if err := json.Unmarshal(data, &js); err != nil {
		return err
	}

	// Decode hex string to bytes
	pubKey, err := hex.DecodeString(js.IdentityPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode public key hex: %w", err)
	}
	identityPubKey, err := keys.ParsePublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	s.IdentityPublicKey = identityPubKey

	s.ID = uint64(js.ID)
	s.Identifier = utils.IndexToIdentifier(js.ID)
	s.AddressRpc = js.Address
	if js.AddressDkg != nil {
		s.AddressDkg = *js.AddressDkg
	} else {
		s.AddressDkg = js.Address // Use the same address for DKG if not specified
	}
	s.CertPath = js.CertPath
	s.ExternalAddress = js.ExternalAddress
	return nil
}

// MarshalProto marshals the signing operator to a protobuf message.
func (s *SigningOperator) MarshalProto() *pb.SigningOperatorInfo {
	return &pb.SigningOperatorInfo{
		Index:      s.ID,
		Identifier: s.Identifier,
		PublicKey:  s.IdentityPublicKey.Serialize(),
		Address:    s.ExternalAddress,
	}
}

// NewGRPConnection creates a new gRPC connection to the signing operator.
func (s *SigningOperator) NewGRPCConnection() (*grpc.ClientConn, error) {
	return common.NewGRPCConnection(s.AddressRpc, s.CertPath, nil)
}

func (s *SigningOperator) NewGRPCConnectionForDKG() (*grpc.ClientConn, error) {
	return common.NewGRPCConnection(s.AddressDkg, s.CertPath, nil)
}
