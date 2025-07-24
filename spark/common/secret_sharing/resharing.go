package secretsharing

import (
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ShareID represents a unique identifier for secret sharing participants.
// Must be non-zero because share ID 0 would give the secret when evaluating polynomials.
// In the SO context, this is derived from operator.ID + 1.
type ShareID uint64

// Scalar wrapper for secp256k1 scalars
type Scalar = secp256k1.ModNScalar

// Point wrapper for secp256k1 curve points
type Point = secp256k1.JacobianPoint

// ScalarBytes encodes a scalar
type ScalarBytes [32]byte

// PointBytes encodes a point
type PointBytes [64]byte // Affine coordinates: 32 bytes X + 32 bytes Y

// Scalar encoding/decoding helpers
func EncodeScalar(s *Scalar) ScalarBytes {
	var result ScalarBytes
	bytes := s.Bytes()
	copy(result[:], bytes[:])
	return result
}

func (sb ScalarBytes) Decode() *Scalar {
	scalar := new(Scalar)
	scalar.SetByteSlice(sb[:])
	return scalar
}

// Point encoding/decoding helpers
func EncodePoint(p *Point) PointBytes {
	var result PointBytes
	p.ToAffine()
	x := p.X.Bytes()
	y := p.Y.Bytes()
	copy(result[0:32], x[:])
	copy(result[32:64], y[:])
	return result
}

func (pb PointBytes) Decode() *Point {
	point := new(Point)
	point.X.SetByteSlice(pb[0:32])
	point.Y.SetByteSlice(pb[32:64])
	point.Z.SetInt(1) // Affine coordinates
	return point
}

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
	Subshare ScalarBytes // ŝ_ij
}

// Round1BroadcastPayload for commitment messages
type Round1BroadcastPayload struct {
	ShareCommitment  PointBytes   // g^s_i
	PolyCommitments  []PointBytes // g^a'_i1, ..., g^a'_i(m'-1)
	SecretCommitment PointBytes   // g^k
}

type Round2Payload struct {
	Decision string // "commit" or "abort"
}

// Round1State contains the results of Round 1 processing
type Round1State struct {
	ReceivedSubshares   map[ShareID]ScalarBytes
	ReceivedCommitments map[ShareID]*Round1BroadcastPayload
}

// === Share Holder Types ===

// OldShareHolder represents a participant in the old access structure
type OldShareHolder struct {
	ID     ShareID
	Share  *Scalar // s_i
	Config *RedistConfig
}

// NewShareHolder represents a participant in the new access structure
type NewShareHolder struct {
	ID     ShareID
	Config *RedistConfig
}

// === Protocol Implementation ===

// NewOldShareHolder creates a new old shareholder
func NewOldShareHolder(id ShareID, share *Scalar, config *RedistConfig) *OldShareHolder {
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
func (o *OldShareHolder) SendSubshares(secretCommitment *Point) ([]DirectMessage[Round1DirectPayload], []BroadcastMessage[Round1BroadcastPayload], error) {
	// Create polynomial for resharing: s_i + a'_i1*x + ... + a'_i(m'-1)*x^(m'-1)
	poly, err := NewScalarPolynomialSharing(o.Share, o.Config.NewThreshold-1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create polynomial: %w", err)
	}

	// Generate commitment polynomial: g^s_i + g^a'_i1*x + ... + g^a'_i(m'-1)*x^(m'-1)
	commitmentPoly := poly.ToPointPolynomial()

	// Create direct messages (subshares for each new party)
	directMessages := make([]DirectMessage[Round1DirectPayload], len(o.Config.NewParties))
	for i, newPartyID := range o.Config.NewParties {
		// Evaluate polynomial at new party's ID to get subshare
		x := new(Scalar)
		x.SetInt(uint32(newPartyID))
		subshare := poly.Eval(x)

		directMessages[i] = DirectMessage[Round1DirectPayload]{
			FromID: o.ID,
			ToID:   newPartyID,
			Payload: Round1DirectPayload{
				Subshare: EncodeScalar(subshare),
			},
		}
	}

	// Encode polynomial commitments
	encodedPolyCommitments := make([]PointBytes, len(commitmentPoly.Coefs[1:]))
	for i, coef := range commitmentPoly.Coefs[1:] {
		encodedPolyCommitments[i] = EncodePoint(coef)
	}

	// Create broadcast message (commitments)
	broadcastMessage := BroadcastMessage[Round1BroadcastPayload]{
		FromID: o.ID,
		Payload: Round1BroadcastPayload{
			ShareCommitment:  EncodePoint(commitmentPoly.Coefs[0]),
			PolyCommitments:  encodedPolyCommitments,
			SecretCommitment: EncodePoint(secretCommitment),
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
	receivedSubshares := make(map[ShareID]ScalarBytes)
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
func (n *NewShareHolder) GenerateNewShare(state *Round1State, decisions []BroadcastMessage[Round2Payload]) (*Scalar, error) {
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

	pairs := make([]*ScalarEval, 0, n.Config.OldThreshold)

	for shareID, subshareBytes := range state.ReceivedSubshares {
		x := new(Scalar).SetInt(uint32(shareID))
		pairs = append(pairs, &ScalarEval{X: x, Y: subshareBytes.Decode()})
	}

	// To generate new share, use Lagrange interpolation to compute
	// s'_j = Σ b_i * ŝ_ij
	newShare := ReconstructScalar(pairs)

	return newShare, nil
}

// === Helper Methods ===

// verifySubshare verifies that
// g^ŝ_ij = g^s_i * prod_{l=1}^{m' - 1} (g^a'_il)^j^l
func (n *NewShareHolder) verifySubshare(subshareBytes ScalarBytes, commitment *Round1BroadcastPayload) error {
	// Left side
	leftSide := new(Point)
	secp256k1.ScalarBaseMultNonConst(subshareBytes.Decode(), leftSide)

	// Right side.
	// Create polynomial from commitments: [g^s_i, g^a'_i1, g^a'_i2, ...]
	coefs := make([]*Point, len(commitment.PolyCommitments)+1)
	coefs[0] = commitment.ShareCommitment.Decode() // g^s_i (constant term)
	for i, polyCommitmentBytes := range commitment.PolyCommitments {
		coefs[i+1] = polyCommitmentBytes.Decode() // g^a'_il coefficients
	}

	p := PointPolynomial{Coefs: coefs}

	j := new(Scalar)
	j.SetInt(uint32(n.ID))

	rightSide := p.Eval(j)

	if !PointEqual(leftSide, rightSide) {
		return errors.New("subshare verification failed")
	}

	return nil
}

// verifySharesValid verifies that
// g^k = prod_i (g^s_i)^b_i where b_i are Lagrange coefficients
func (n *NewShareHolder) verifySharesValid(receivedCommitments map[ShareID]*Round1BroadcastPayload) error {
	// Get first secret commitment (they should all be the same)
	var gk *Point
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
		if !PointEqual(gk, commitment.SecretCommitment.Decode()) {
			return fmt.Errorf("inconsistent secret commitment from share %d", shareID)
		}
	}

	// Create (x_i, g^s_i) pairs for Lagrange interpolation at zero
	pairs := make([]*PointEval, 0, n.Config.OldThreshold)

	for shareID, commitment := range receivedCommitments {
		x := new(Scalar)
		x.SetInt(uint32(shareID))
		pairs = append(pairs, &PointEval{X: x, Y: commitment.ShareCommitment.Decode()})

		// Only use first m parties for interpolation
		if len(pairs) >= n.Config.OldThreshold {
			break
		}
	}

	result := ReconstructPoint(pairs)

	if !PointEqual(gk, result) {
		return errors.New("SHARES-VALID condition not satisfied")
	}

	return nil
}

// TODO: Replace with secp256k1.EquivalentNonConst from newer module version.
func PointEqual(p *Point, q *Point) bool {
	// TODO: Do we need a special case for the neutral point?
	p.ToAffine()
	q.ToAffine()
	return p.X == q.X && p.Y == q.Y && p.Z == q.Z
}
