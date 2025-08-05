package wallet

import (
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/keys"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
)

// Config is the configuration for the wallet.
type Config struct {
	// Network is the network to use for the wallet.
	Network common.Network
	// SigningOperators contains all the signing operators using identifier as key.
	SigningOperators map[string]*so.SigningOperator
	// CoodinatorIdentifier is the identifier of the signing operator as the coodinator.
	CoodinatorIdentifier string
	// FrostSignerAddress is the address of the Frost signer.
	FrostSignerAddress string
	// IdentityPrivateKey is the identity private key of the wallet.
	IdentityPrivateKey keys.Private
	// Threshold is the min signing operators.
	Threshold int
	// SparkServiceProviderIdentityPublicKey is the identity public key of the Spark service provider.
	SparkServiceProviderIdentityPublicKey keys.Public
	// UseTokenTransactionSchnorrSignatures determines whether to use Schnorr signatures (true) or ECDSA signatures (false)
	UseTokenTransactionSchnorrSignatures bool
	// CoordinatorDatabaseURI is the database URI for the coordinator.
	CoordinatorDatabaseURI string
}

// CoodinatorAddress returns coodinator address.
func (c *Config) CoodinatorAddress() string {
	return c.SigningOperators[c.CoodinatorIdentifier].AddressRpc
}

// IdentityPublicKey returns the identity public key.
func (c *Config) IdentityPublicKey() keys.Public {
	return c.IdentityPrivateKey.Public()
}

func (c *Config) ProtoNetwork() pb.Network {
	network, err := common.ProtoNetworkFromNetwork(c.Network)
	if err != nil {
		panic(err)
	}
	return network
}
