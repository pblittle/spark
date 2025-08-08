package secretsharing

import (
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightsparkdev/spark/common/secret_sharing/curve"
	"github.com/lightsparkdev/spark/common/secret_sharing/polynomial"
)

// ShareID represents a unique identifier for secret sharing participants.
// Must be non-zero because share ID 0 would give the secret when evaluating polynomials.
// In the SO context, this is derived from operator.ID + 1.
type ShareID uint64

// Protocol configuration
type RedistConfig struct {
	OldThreshold int       // m
	NewThreshold int       // m'
	OldParties   []ShareID // n parties
	NewParties   []ShareID // n' parties
}

// === Message Types ===

// DirectMessage is a point-to-point message directly between two parties
type DirectMessage[T any] struct {
	FromID  ShareID
	ToID    ShareID
	Payload T
}

// BroadcastMessage is a message that must be verifiably received identically by all parties
type BroadcastMessage[T any] struct {
	FromID  ShareID
	Payload T
}

// === Payload Types ===

// TODO: Rename since it is only round 1 of the new shareholder's but round 2 within the overall resharing. Too confusing
// Round1DirectPayload for point-to-point subshare messages
type Round1DirectPayload struct {
	Subshare curve.ScalarBytes // ŝ_ij
}

// Round1BroadcastPayload for commitment messages
type Round1BroadcastPayload struct {
	ShareCommitment  curve.PointBytes   // g^s_i
	PolyCommitments  []curve.PointBytes // g^a'_i1, ..., g^a'_i(m'-1)
	SecretCommitment curve.PointBytes   // g^k
}

type Round2Payload struct {
	Decision string // "commit" or "abort"
}

// Round1State contains the results of Round 1 processing
type Round1State struct {
	ReceivedSubshares   map[ShareID]curve.ScalarBytes
	ReceivedCommitments map[ShareID]*Round1BroadcastPayload
}

// === Share Holder Types ===

// OldShareHolder represents a participant in the old access structure
type OldShareHolder struct {
	ID     ShareID
	Share  *curve.Scalar // s_i
	Config *RedistConfig
}

// NewShareHolder represents a participant in the new access structure
type NewShareHolder struct {
	ID     ShareID
	Config *RedistConfig
}

// === Protocol Implementation ===

// NewOldShareHolder creates a new old shareholder
func NewOldShareHolder(id ShareID, share *curve.Scalar, config *RedistConfig) *OldShareHolder {
	return &OldShareHolder{
		ID:     id,
		Share:  share,
		Config: config,
	}
}

// NewNewShareHolder creates a new shareholder
func NewNewShareHolder(id ShareID, config *RedistConfig) *NewShareHolder {
	return &NewShareHolder{
		ID:     id,
		Config: config,
	}
}

// === Old Shareholder Methods ===

// SendSubshares sends subshares to new parties and broadcasts commitments (Protocol Round 1)
func (o *OldShareHolder) SendSubshares(secretCommitment *curve.Point) ([]DirectMessage[Round1DirectPayload], []BroadcastMessage[Round1BroadcastPayload], error) {
	// Create polynomial for resharing: s_i + a'_i1*x + ... + a'_i(m'-1)*x^(m'-1)
	poly, err := polynomial.NewScalarPolynomialSharing(o.Share, o.Config.NewThreshold-1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create polynomial: %w", err)
	}

	// Generate commitment polynomial: g^s_i + g^a'_i1*x + ... + g^a'_i(m'-1)*x^(m'-1)
	commitmentPoly := poly.ToPointPolynomial()

	// Create direct messages (subshares for each new party)
	directMessages := make([]DirectMessage[Round1DirectPayload], len(o.Config.NewParties))
	for i, newPartyID := range o.Config.NewParties {
		// Evaluate polynomial at new party's ID to get subshare
		x := new(curve.Scalar)
		x.SetInt(uint32(newPartyID))
		subshare := poly.Eval(x)

		directMessages[i] = DirectMessage[Round1DirectPayload]{
			FromID: o.ID,
			ToID:   newPartyID,
			Payload: Round1DirectPayload{
				Subshare: curve.EncodeScalar(subshare),
			},
		}
	}

	// Encode polynomial commitments
	encodedPolyCommitments := make([]curve.PointBytes, len(commitmentPoly.Coefs[1:]))
	for i, coef := range commitmentPoly.Coefs[1:] {
		encodedPolyCommitments[i] = curve.EncodePoint(coef)
	}

	// Create broadcast message (commitments)
	broadcastMessage := BroadcastMessage[Round1BroadcastPayload]{
		FromID: o.ID,
		Payload: Round1BroadcastPayload{
			ShareCommitment:  curve.EncodePoint(commitmentPoly.Coefs[0]),
			PolyCommitments:  encodedPolyCommitments,
			SecretCommitment: curve.EncodePoint(secretCommitment),
		},
	}

	return directMessages, []BroadcastMessage[Round1BroadcastPayload]{broadcastMessage}, nil
}

// === New Shareholder Methods ===

// VerifyAndDecide - New shareholder processes received subshares and commitments, verifies, and broadcasts decision (Protocol Round 2)
func (n *NewShareHolder) VerifyAndDecide(
	directMessages []DirectMessage[Round1DirectPayload],
	broadcastMessages []BroadcastMessage[Round1BroadcastPayload],
) (*Round1State, []BroadcastMessage[Round2Payload], error) {
	// Collect received data
	receivedSubshares := make(map[ShareID]curve.ScalarBytes)
	receivedCommitments := make(map[ShareID]*Round1BroadcastPayload)

	// Process direct messages (subshares)
	for _, msg := range directMessages {
		if msg.ToID != n.ID {
			continue // Skip messages not for us
		}
		// Subshares are always present in direct messages by construction
		receivedSubshares[msg.FromID] = msg.Payload.Subshare
	}

	// Process broadcast messages (commitments)
	for _, broadcast := range broadcastMessages {
		receivedCommitments[broadcast.FromID] = &broadcast.Payload
	}

	// Determine decision based on verification
	decision := "commit"
	var verificationError error

	if len(receivedSubshares) == n.Config.OldThreshold {
		// Verify subshares against commitments using Feldman VSS
		for shareID, subshareBytes := range receivedSubshares {
			commitment, exists := receivedCommitments[shareID]
			if !exists {
				decision = "abort"
				verificationError = fmt.Errorf("missing commitment from share %d", shareID)
				break
			}

			if err := n.verifySubshare(subshareBytes, commitment); err != nil {
				decision = "abort"
				verificationError = fmt.Errorf("subshare verification failed for share %d: %w", shareID, err)
				break
			}
		}

		// Verify SHARES-VALID condition: g^k = prod_i (g^s_i)^b_i
		if decision == "commit" {
			if err := n.verifySharesValid(receivedCommitments); err != nil {
				decision = "abort"
				verificationError = fmt.Errorf("SHARES-VALID verification failed: %w", err)
			}
		}
	} else {
		decision = "abort"

		if len(receivedSubshares) < n.Config.OldThreshold {
			verificationError = fmt.Errorf("insufficient subshares: got %d, need %d",
				len(receivedSubshares), n.Config.OldThreshold)
		} else if len(receivedSubshares) > n.Config.OldThreshold {
			verificationError = fmt.Errorf("too many subshares: got %d, need %d",
				len(receivedSubshares), n.Config.OldThreshold)
		}
	}

	state := &Round1State{
		ReceivedSubshares:   receivedSubshares,
		ReceivedCommitments: receivedCommitments,
	}

	// Broadcast decision
	decisionBroadcast := BroadcastMessage[Round2Payload]{
		FromID: n.ID,
		Payload: Round2Payload{
			Decision: decision,
		},
	}

	// If we decided to abort, return the error for logging/debugging
	if decision == "abort" {
		return state, []BroadcastMessage[Round2Payload]{decisionBroadcast}, verificationError
	}

	return state, []BroadcastMessage[Round2Payload]{decisionBroadcast}, nil
}

// GenerateNewShare - New shareholder checks decisions from all parties and generates share if all committed (Protocol Round 3)
func (n *NewShareHolder) GenerateNewShare(state *Round1State, decisions []BroadcastMessage[Round2Payload]) (*curve.Scalar, error) {
	// Check that we have decisions from all new parties
	expectedParties := len(n.Config.NewParties)
	if len(decisions) < expectedParties {
		return nil, fmt.Errorf("insufficient decisions: got %d, expected %d", len(decisions), expectedParties)
	}

	// Verify all parties committed
	for _, decision := range decisions {
		if decision.Payload.Decision != "commit" {
			return nil, fmt.Errorf("party %d aborted, protocol failed", decision.FromID)
		}
	}

	pairs := make([]*polynomial.ScalarEval, 0, n.Config.OldThreshold)

	for shareID, subshareBytes := range state.ReceivedSubshares {
		x := new(curve.Scalar).SetInt(uint32(shareID))
		pairs = append(pairs, &polynomial.ScalarEval{X: x, Y: subshareBytes.Decode()})
	}

	// To generate new share, use Lagrange interpolation to compute
	// s'_j = Σ b_i * ŝ_ij
	newShare := polynomial.ReconstructScalar(pairs)

	return newShare, nil
}

// === Helper Methods ===

// verifySubshare verifies that
// g^ŝ_ij = g^s_i * prod_{l=1}^{m' - 1} (g^a'_il)^j^l
func (n *NewShareHolder) verifySubshare(subshareBytes curve.ScalarBytes, commitment *Round1BroadcastPayload) error {
	// Left side
	leftSide := new(curve.Point)
	secp256k1.ScalarBaseMultNonConst(subshareBytes.Decode(), leftSide)

	// Right side.
	// Create polynomial from commitments: [g^s_i, g^a'_i1, g^a'_i2, ...]
	coefs := make([]*curve.Point, len(commitment.PolyCommitments)+1)
	coefs[0] = commitment.ShareCommitment.Decode() // g^s_i (constant term)
	for i, polyCommitmentBytes := range commitment.PolyCommitments {
		coefs[i+1] = polyCommitmentBytes.Decode() // g^a'_il coefficients
	}

	p := polynomial.PointPolynomial{Coefs: coefs}

	j := new(curve.Scalar)
	j.SetInt(uint32(n.ID))

	rightSide := p.Eval(j)

	if !curve.PointEqual(leftSide, rightSide) {
		return errors.New("subshare verification failed")
	}

	return nil
}

// verifySharesValid verifies that
// g^k = prod_i (g^s_i)^b_i where b_i are Lagrange coefficients
func (n *NewShareHolder) verifySharesValid(receivedCommitments map[ShareID]*Round1BroadcastPayload) error {
	// Get first secret commitment (they should all be the same)
	var gk *curve.Point
	for _, commitment := range receivedCommitments {
		// Secret commitments are always present in broadcast messages by construction
		gk = commitment.SecretCommitment.Decode()
		break
	}

	if gk == nil {
		return errors.New("no secret commitment found")
	}

	// Verify all secret commitments are the same
	for shareID, commitment := range receivedCommitments {
		if !curve.PointEqual(gk, commitment.SecretCommitment.Decode()) {
			return fmt.Errorf("inconsistent secret commitment from share %d", shareID)
		}
	}

	// Create (x_i, g^s_i) pairs for Lagrange interpolation at zero
	pairs := make([]*polynomial.PointEval, 0, n.Config.OldThreshold)

	for shareID, commitment := range receivedCommitments {
		x := new(curve.Scalar)
		x.SetInt(uint32(shareID))
		pairs = append(pairs, &polynomial.PointEval{X: x, Y: commitment.ShareCommitment.Decode()})

		// Only use first m parties for interpolation
		if len(pairs) >= n.Config.OldThreshold {
			break
		}
	}

	result := polynomial.ReconstructPoint(pairs)

	if !curve.PointEqual(gk, result) {
		return errors.New("SHARES-VALID condition not satisfied")
	}

	return nil
}
