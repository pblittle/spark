package tokens

import (
	"context"
	"fmt"
	"math/big"

	"github.com/lightsparkdev/spark/common/logging"
	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/tokencreate"
	"github.com/lightsparkdev/spark/so/ent/tokenoutput"
	"github.com/lightsparkdev/spark/so/ent/tokentransaction"
)

// ValidateMintDoesNotExceedMaxSupply validates that a mint transaction doesn't exceed the token's max supply.
// This validation is shared between the prepare and sign handlers.
func ValidateMintDoesNotExceedMaxSupply(ctx context.Context, tokenTransaction *tokenpb.TokenTransaction) error {
	mintAmount := new(big.Int)
	for _, output := range tokenTransaction.GetTokenOutputs() {
		amount := new(big.Int).SetBytes(output.GetTokenAmount())
		mintAmount.Add(mintAmount, amount)
	}

	// Extract token identification from proto transaction
	var tokenIdentifier []byte
	var issuerPublicKey []byte

	if tokenTransaction.GetMintInput() != nil {
		tokenIdentifier = tokenTransaction.GetMintInput().GetTokenIdentifier()
		issuerPublicKey = tokenTransaction.GetMintInput().GetIssuerPublicKey()
	} else if len(tokenTransaction.GetTokenOutputs()) > 0 {
		output := tokenTransaction.GetTokenOutputs()[0]
		tokenIdentifier = output.GetTokenIdentifier()
		issuerPublicKey = output.GetTokenPublicKey()
	}

	err := validateMintAgainstMaxSupplyCore(ctx, mintAmount, tokenIdentifier, issuerPublicKey)
	if err != nil {
		return FormatErrorWithTransactionProto(err.Error(), tokenTransaction, err)
	}
	return nil
}

// ValidateMintDoesNotExceedMaxSupplyEnt validates that a mint transaction doesn't exceed the token's max supply.
// This is a more efficient version that works with Ent entities directly without proto conversion.
func ValidateMintDoesNotExceedMaxSupplyEnt(ctx context.Context, tokenTransaction *ent.TokenTransaction) error {
	mintAmount := new(big.Int)
	for _, output := range tokenTransaction.Edges.CreatedOutput {
		amount := new(big.Int).SetBytes(output.TokenAmount)
		mintAmount.Add(mintAmount, amount)
	}

	var tokenIdentifier []byte
	var issuerPublicKey []byte
	if tokenTransaction.Edges.Mint != nil {
		tokenIdentifier = tokenTransaction.Edges.Mint.TokenIdentifier
		issuerPublicKey = tokenTransaction.Edges.Mint.IssuerPublicKey
	} else {
		return fmt.Errorf("can not verify max supply for mint transaction because no mint input was found")
	}

	err := validateMintAgainstMaxSupplyCore(ctx, mintAmount, tokenIdentifier, issuerPublicKey)
	if err != nil {
		return FormatErrorWithTransactionEnt(err.Error(), tokenTransaction, err)
	}
	return nil
}

// validateMintAgainstMaxSupplyCore contains the core validation logic that both proto and Ent versions can use.
func validateMintAgainstMaxSupplyCore(ctx context.Context, mintAmount *big.Int, tokenIdentifier []byte, issuerPublicKey []byte) error {
	logger := logging.GetLoggerFromContext(ctx)
	db, err := ent.GetDbFromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get or create current tx for request: %w", err)
	}

	// Get token metadata
	var tokenCreate *ent.TokenCreate

	var identifierInfo string
	if tokenIdentifier != nil {
		tokenCreate, err = db.TokenCreate.Query().Where(tokencreate.TokenIdentifierEQ(tokenIdentifier)).First(ctx)
		identifierInfo = fmt.Sprintf("token identifier: %x", tokenIdentifier)
	} else if issuerPublicKey != nil {
		tokenCreate, err = db.TokenCreate.Query().Where(tokencreate.IssuerPublicKeyEQ(issuerPublicKey)).First(ctx)
		identifierInfo = fmt.Sprintf("issuer public key: %x", issuerPublicKey)
	} else {
		return fmt.Errorf("no token identifier or issuer public key provided")
	}
	if ent.IsNotFound(err) {
		logger.Info("Token metadata not found - minting not allowed", "identifier_info", identifierInfo)
		return fmt.Errorf("minting not allowed because a created token was not found for %s", identifierInfo)
	}
	if err != nil {
		return fmt.Errorf("failed to get token metadata for %s: %w", identifierInfo, err)
	}

	maxSupply := new(big.Int).SetBytes(tokenCreate.MaxSupply)
	if maxSupply.Cmp(big.NewInt(0)) == 0 {
		// Max supply of 0 means infinite supply.
		return nil
	}

	// Calculate current supply
	var currentSupply *big.Int
	if tokenIdentifier != nil {
		currentSupply, err = calculateCurrentSupplyByTokenIdentifier(ctx, tokenIdentifier)
	} else {
		currentSupply, err = calculateCurrentSupplyByIssuerKey(ctx, issuerPublicKey)
	}
	if err != nil {
		return fmt.Errorf("failed to calculate current minted supply: %w", err)
	}

	// Validate against max supply
	newTotalSupply := new(big.Int).Add(currentSupply, mintAmount)
	if newTotalSupply.Cmp(maxSupply) > 0 {
		return fmt.Errorf("mint would exceed max supply: total supply after mint (%s) would exceed max supply (%s)",
			newTotalSupply.String(), maxSupply.String())
	}

	return nil
}

// calculateCurrentSupplyByTokenIdentifier calculates the current minted supply for a token by token identifier.
func calculateCurrentSupplyByTokenIdentifier(ctx context.Context, tokenIdentifier []byte) (*big.Int, error) {
	return calculateCurrentSupply(ctx, func(q *ent.TokenOutputQuery) *ent.TokenOutputQuery {
		return q.Where(tokenoutput.TokenIdentifierEQ(tokenIdentifier))
	})
}

// calculateCurrentSupplyByIssuerKey calculates the current minted supply for a token by issuer public key.
func calculateCurrentSupplyByIssuerKey(ctx context.Context, issuerPublicKey []byte) (*big.Int, error) {
	return calculateCurrentSupply(ctx, func(q *ent.TokenOutputQuery) *ent.TokenOutputQuery {
		return q.Where(tokenoutput.TokenPublicKeyEQ(issuerPublicKey))
	})
}

// calculateCurrentSupply is a helper function that executes the common query logic.
func calculateCurrentSupply(ctx context.Context, whereClause func(*ent.TokenOutputQuery) *ent.TokenOutputQuery) (*big.Int, error) {
	db, err := ent.GetDbFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get or create current tx for request: %w", err)
	}

	outputs, err := whereClause(db.TokenOutput.Query()).
		Where(tokenoutput.HasOutputCreatedTokenTransactionWith(
			tokentransaction.StatusEQ(st.TokenTransactionStatusSigned),
			tokentransaction.HasMint(),
		)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signed mint outputs: %w", err)
	}

	totalMinted := new(big.Int)
	for _, out := range outputs {
		amount := new(big.Int).SetBytes(out.TokenAmount)
		totalMinted.Add(totalMinted, amount)
	}
	return totalMinted, nil
}
