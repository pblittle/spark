package sparktesting

import (
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/rpcclient"
)

var (
	ErrClientAlreadyInitialized = fmt.Errorf("regtest client already initialized")

	bitcoinClientInstance *rpcclient.Client
	bitcoinClientOnce     sync.Once
)

func newClient() (*rpcclient.Client, error) {
	connConfig := rpcclient.ConnConfig{
		Host:         "127.0.0.1:8332",
		User:         "testutil",
		Pass:         "testutilpassword",
		Params:       "regtest",
		DisableTLS:   true,
		HTTPPostMode: true,
	}
	return rpcclient.New(
		&connConfig,
		nil,
	)
}

func InitBitcoinClient() (*rpcclient.Client, error) {
	err := ErrClientAlreadyInitialized

	bitcoinClientOnce.Do(func() {
		bitcoinClientInstance, err = newClient()
	})

	return bitcoinClientInstance, err
}

func GetBitcoinClient() *rpcclient.Client {
	return bitcoinClientInstance
}
