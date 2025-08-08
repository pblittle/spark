package curve

import "github.com/decred/dcrd/dcrec/secp256k1/v4"

type Scalar = secp256k1.ModNScalar
type Point = secp256k1.JacobianPoint

type ScalarBytes [32]byte
type PointBytes [64]byte

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

func ScalarFromInt(n uint32) *secp256k1.ModNScalar {
	s := new(secp256k1.ModNScalar)
	s.SetInt(n)
	return s
}

// TODO: Replace with secp256k1.EquivalentNonConst from newer module version.
func PointEqual(p *Point, q *Point) bool {
	// TODO: Do we need a special case for the neutral point?
	p.ToAffine()
	q.ToAffine()
	return p.X == q.X && p.Y == q.Y && p.Z == q.Z
}
