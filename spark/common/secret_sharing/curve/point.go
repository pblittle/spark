package curve

import (
	"encoding/json"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightsparkdev/spark/common/keys"
)

// Point is a secp256k1 point. It is guaranteed to be a valid point on the curve.
type Point struct {
	// Make struct not comparable. Otherwise the operator == is available,
	// and its semantics are wrong since a curve point has many Jacobian representations.
	_ [0]func()

	point secp256k1.JacobianPoint
}

// PointBytesLen is the number of bytes in a serialized point.
const PointBytesLen = 1 + secp256k1.PubKeyBytesLenCompressed

const (
	pointSerialDiscriminantIdentity    = 0
	pointSerialDiscriminantNonIdentity = 1
)

// ParsePoint creates a point from a serialization.
func ParsePoint(serial []byte) (Point, error) {
	if len(serial) != PointBytesLen {
		return Point{}, fmt.Errorf("point must be %d bytes", PointBytesLen)
	}

	serialDiscriminant := serial[0]
	serialPubKey := serial[1:]

	switch serialDiscriminant {
	case pointSerialDiscriminantIdentity:
		return IdentityPoint(), nil

	case pointSerialDiscriminantNonIdentity:
		pubKey, err := secp256k1.ParsePubKey(serialPubKey[:])
		if err != nil {
			return Point{}, fmt.Errorf("invalid public key part: %w", err)
		}

		var parse Point
		pubKey.AsJacobian(&parse.point)

		return parse, nil

	default:
		return Point{}, fmt.Errorf("invalid discriminant %d", serialDiscriminant)
	}
}

// Serialize creates a serialization of this point.
func (p Point) Serialize() []byte {
	var serial [PointBytesLen]byte

	serialDiscriminant := &serial[0]
	serialPubKey := serial[1:]

	pubKey, err := p.ToPublicKey()
	if err != nil {
		*serialDiscriminant = pointSerialDiscriminantIdentity
	} else {
		*serialDiscriminant = pointSerialDiscriminantNonIdentity
		copy(serialPubKey, pubKey.Serialize())
	}

	return serial[:]
}

// NewPointFromPublicKey returns the point corresponding to the passed public key.
func NewPointFromPublicKey(pubKey keys.Public) Point {
	pt := Point{}
	pubKey.ToBTCEC().AsJacobian(&pt.point)

	return pt
}

// ToPublicKey creates a public key representation of this point.
// It returns an error if this is the identity point, which has no public key representation.
func (p Point) ToPublicKey() (keys.Public, error) {
	if p.isIdentity() {
		return keys.Public{}, fmt.Errorf("identity point cannot be a public key")
	}

	p.point.ToAffine()
	pubKey := secp256k1.NewPublicKey(&p.point.X, &p.point.Y)

	return keys.PublicKeyFromKey(*pubKey), nil
}

// IdentityPoint returns the curve group identity.
func IdentityPoint() Point {
	return Point{}
}

// Neg returns a copy of this point negated.
func (p Point) Neg() Point {
	return *p.SetNeg()
}

// SetNeg negates this point. This point is modified.
//
// This point is returned to allow method chaining.
func (p *Point) SetNeg() *Point {
	p.point.Y.Normalize().Negate(1).Normalize()
	return p
}

// Add returns a copy of this point with the passed point added to it.
func (p Point) Add(q Point) Point {
	return *p.SetAdd(&q)
}

// SetAdd adds the passed point to this point. This point is modified.
//
// This point is returned to allow method chaining.
func (p *Point) SetAdd(q *Point) *Point {
	secp256k1.AddNonConst(&p.point, &q.point, &p.point)
	return p
}

// Sub returns a copy of this point with the passed point subtracted from it.
func (p Point) Sub(q Point) Point {
	return *p.SetSub(&q)
}

// SetSub subtracts the passed point from this point. This point is modified.
//
// This point is returned to allow method chaining.
func (p *Point) SetSub(q *Point) *Point {
	// Use the fact that s - t = -(-s + t) to not modify t.
	p.SetNeg().SetAdd(q).SetNeg()
	return p
}

// ScalarMul returns a copy of this point multiplied by the passed scalar.
func (p Point) ScalarMul(s Scalar) Point {
	return *p.SetScalarMul(&s)
}

// SetScalarMul multiplies this point by the passed scalar. This point is modified.
//
// This point is returned to allow method chaining.
func (p *Point) SetScalarMul(s *Scalar) *Point {
	secp256k1.ScalarMultNonConst(&s.scalar, &p.point, &p.point)
	return p
}

// isIdentity returns true if this point is the curve group identity.
func (p Point) isIdentity() bool {
	isIdentityStandard := p.point.Z.IsZero()

	// An example of where this arises: `p = ScalarFromInt(0).Point()`.
	// It appears to behave algebraically as the identity point.
	isIdentityNonStandard := p.point.Z.IsOne() && p.point.X.IsZero() && p.point.Y.IsZero()

	return isIdentityStandard || isIdentityNonStandard
}

// Equals returns true if this and the passed point represent the same secp256k1 point and false otherwise.
func (p Point) Equals(q Point) bool {
	// NOTE: If a newer module version is used, this can instead use `secp256k1.EquivalentNonConst`.
	return p.Sub(q).isIdentity()
}

// MarshalJSON implements json.Marshaler.
func (p Point) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.Serialize())
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *Point) UnmarshalJSON(jsonData []byte) error {
	pointSerial := make([]byte, PointBytesLen)
	if err := json.Unmarshal(jsonData, &pointSerial); err != nil {
		return fmt.Errorf("failed to unmarshal point: %w", err)
	}

	point, err := ParsePoint(pointSerial)
	if err != nil {
		return fmt.Errorf("failed to parse unmarshaled point: %w", err)
	}
	p.point = point.point

	return nil
}
