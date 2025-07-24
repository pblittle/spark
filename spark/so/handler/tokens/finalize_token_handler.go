package tokens

import (
	"context"
	"fmt"

	sparkpb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/authz"
	"github.com/lightsparkdev/spark/so/lrc20"
	"github.com/lightsparkdev/spark/so/tokens"
	"google.golang.org/protobuf/types/known/emptypb"
)

type FinalizeTokenHandler struct {
	config      *so.Config
	lrc20Client *lrc20.Client
}

// NewFinalizeTokenHandler creates a new FinalizeTransactionHandler.
func NewFinalizeTokenHandler(config *so.Config, lrc20Client *lrc20.Client) *FinalizeTokenHandler {
	return &FinalizeTokenHandler{
		config:      config,
		lrc20Client: lrc20Client,
	}
}

// FinalizeTokenTransaction takes the revocation private keys for spent outputs and updates their status to finalized.
func (h *FinalizeTokenHandler) FinalizeTokenTransaction(
	ctx context.Context,
	req *sparkpb.FinalizeTokenTransactionRequest,
) (*emptypb.Empty, error) {
	if err := authz.EnforceSessionIdentityPublicKeyMatches(ctx, h.config, req.IdentityPublicKey); err != nil {
		return nil, fmt.Errorf("%s: %w", tokens.ErrIdentityPublicKeyAuthFailed, err)
	}

	internalFinalizeHandler := NewInternalFinalizeTokenHandler(h.config, h.lrc20Client)
	return internalFinalizeHandler.FinalizeTokenTransactionInternal(ctx, req)
}
