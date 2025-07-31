package secretsharing

import (
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
)

// Helper function to create a point from a scalar (g^scalar)
func pointFromScalar(scalar *secp256k1.ModNScalar) *secp256k1.JacobianPoint {
	point := new(secp256k1.JacobianPoint)
	secp256k1.ScalarBaseMultNonConst(scalar, point)
	return point
}

// Test basic ScalarPolynomial creation and evaluation
func TestScalarPolynomialBasic(t *testing.T) {
	// Test constant polynomial (degree 0)
	secret := scalarFromInt(42)
	poly, err := NewScalarPolynomialSharing(secret, 0)
	if err != nil {
		t.Fatalf("Failed to create constant polynomial: %v", err)
	}

	if len(poly.Coefs) != 1 {
		t.Errorf("Expected 1 coefficient for degree 0, got %d", len(poly.Coefs))
	}

	if !poly.Coefs[0].Equals(secret) {
		t.Errorf("Constant term should equal secret")
	}

	// Test evaluation at various points
	testPoints := []uint32{0, 1, 5, 100}
	for _, x := range testPoints {
		xScalar := scalarFromInt(x)
		result := poly.Eval(xScalar)
		if !result.Equals(secret) {
			t.Errorf("Constant polynomial should return %s at x=%d, got %s",
				secret.String(), x, result.String())
		}
	}
}

// Test ScalarPolynomial with higher degrees
func TestScalarPolynomialDegrees(t *testing.T) {
	secret := scalarFromInt(123)

	// Test polynomials of various degrees
	degrees := []int{1, 2, 5, 10}

	for _, degree := range degrees {
		poly, err := NewScalarPolynomialSharing(secret, degree)
		if err != nil {
			t.Fatalf("Failed to create polynomial of degree %d: %v", degree, err)
		}

		if len(poly.Coefs) != degree+1 {
			t.Errorf("Expected %d coefficients for degree %d, got %d",
				degree+1, degree, len(poly.Coefs))
		}

		// Constant term should be the secret
		if !poly.Coefs[0].Equals(secret) {
			t.Errorf("Constant term should equal secret for degree %d", degree)
		}

		// Evaluation at x=0 should return the secret
		zero := scalarFromInt(0)
		result := poly.Eval(zero)
		if !result.Equals(secret) {
			t.Errorf("P(0) should equal secret for degree %d, got %s",
				degree, result.String())
		}
	}
}

// Test manual polynomial creation and evaluation
func TestManualScalarPolynomial(t *testing.T) {
	// Create polynomial: 5 + 3x + 2x^2
	coefs := []*secp256k1.ModNScalar{
		scalarFromInt(5), // constant term
		scalarFromInt(3), // x coefficient
		scalarFromInt(2), // x^2 coefficient
	}

	poly := &ScalarPolynomial{Coefs: coefs}

	// Test known evaluations
	testCases := []struct {
		x        uint32
		expected uint32
	}{
		{0, 5},  // 5 + 3*0 + 2*0^2 = 5
		{1, 10}, // 5 + 3*1 + 2*1^2 = 10
		{2, 19}, // 5 + 3*2 + 2*2^2 = 19
		{3, 32}, // 5 + 3*3 + 2*3^2 = 32
	}

	for _, tc := range testCases {
		x := scalarFromInt(tc.x)
		expected := scalarFromInt(tc.expected)
		result := poly.Eval(x)

		if !result.Equals(expected) {
			t.Errorf("P(%d) expected %d, got %s", tc.x, tc.expected, result.String())
		}
	}
}

// Test PointPolynomial creation and evaluation
func TestPointPolynomial(t *testing.T) {
	// Create polynomial with point coefficients: G*5 + G*3*x + G*2*x^2
	coefs := []*secp256k1.JacobianPoint{
		pointFromScalar(scalarFromInt(5)), // G*5
		pointFromScalar(scalarFromInt(3)), // G*3
		pointFromScalar(scalarFromInt(2)), // G*2
	}

	poly := &PointPolynomial{Coefs: coefs}

	// Test evaluation - should give same results as scalar version but as points
	testCases := []struct {
		x        uint32
		expected uint32
	}{
		{0, 5},
		{1, 10},
		{2, 19},
		{3, 32},
	}

	for _, tc := range testCases {
		x := scalarFromInt(tc.x)
		expectedPoint := pointFromScalar(scalarFromInt(tc.expected))
		result := poly.Eval(x)

		if !PointEqual(result, expectedPoint) {
			t.Errorf("Point polynomial P(%d) gave incorrect result", tc.x)
		}
	}
}

// Test Lagrange interpolation for scalars
func TestScalarLagrangeInterpolation(t *testing.T) {
	// Test with known polynomial: 7 + 4x + 2x^2
	secret := scalarFromInt(7)
	coefs := []*secp256k1.ModNScalar{
		secret,
		scalarFromInt(4),
		scalarFromInt(2),
	}
	poly := &ScalarPolynomial{Coefs: coefs}

	// Generate evaluation points
	points := []*ScalarEval{
		{X: scalarFromInt(1), Y: poly.Eval(scalarFromInt(1))}, // P(1) = 13
		{X: scalarFromInt(2), Y: poly.Eval(scalarFromInt(2))}, // P(2) = 23
		{X: scalarFromInt(3), Y: poly.Eval(scalarFromInt(3))}, // P(3) = 37
	}

	// Reconstruct at x=0 (should give us the secret)
	reconstructed := ReconstructScalar(points)

	if !reconstructed.Equals(secret) {
		t.Errorf("Scalar Lagrange interpolation failed")
		t.Errorf("Expected: %s", secret.String())
		t.Errorf("Got: %s", reconstructed.String())
	}
}

// Test Lagrange interpolation for points
func TestPointLagrangeInterpolation(t *testing.T) {
	// Test with known polynomial over points: G*7 + G*4*x + G*2*x^2
	secret := scalarFromInt(7)
	secretPoint := pointFromScalar(secret)

	coefs := []*secp256k1.JacobianPoint{
		secretPoint,
		pointFromScalar(scalarFromInt(4)),
		pointFromScalar(scalarFromInt(2)),
	}
	poly := &PointPolynomial{Coefs: coefs}

	// Generate evaluation points
	points := []*PointEval{
		{X: scalarFromInt(1), Y: poly.Eval(scalarFromInt(1))},
		{X: scalarFromInt(2), Y: poly.Eval(scalarFromInt(2))},
		{X: scalarFromInt(3), Y: poly.Eval(scalarFromInt(3))},
	}

	// Reconstruct at x=0 (should give us the secret point)
	reconstructed := ReconstructPoint(points)

	if !PointEqual(reconstructed, secretPoint) {
		t.Errorf("Point Lagrange interpolation failed to reconstruct secret point")
	}
}

// Test threshold secret sharing scenario
func TestThresholdSecretSharing(t *testing.T) {
	secret := scalarFromInt(999)
	threshold := 3
	numShares := 5

	// Create polynomial for (3,5) threshold scheme
	poly, err := NewScalarPolynomialSharing(secret, threshold-1)
	if err != nil {
		t.Fatalf("Failed to create polynomial: %v", err)
	}

	// Generate shares
	shares := make([]*ScalarEval, numShares)
	for i := range numShares {
		x := scalarFromInt(uint32(i + 1)) // Party IDs 1,2,3,4,5
		y := poly.Eval(x)
		shares[i] = &ScalarEval{X: x, Y: y}
	}

	// Test that any 3 shares can reconstruct the secret
	for i := 0; i <= numShares-threshold; i++ {
		subset := shares[i : i+threshold]
		reconstructed := ReconstructScalar(subset)

		if !reconstructed.Equals(secret) {
			t.Errorf("Failed to reconstruct secret with shares %d-%d",
				i+1, i+threshold)
		}
	}

	// Test that 2 shares cannot reconstruct (should give wrong result)
	twoShares := shares[0:2]
	wrongReconstruction := ReconstructScalar(twoShares)

	if wrongReconstruction.Equals(secret) {
		t.Errorf("Two shares should not be able to reconstruct the secret")
	}
}

func TestScalarPolynomialEmpty(t *testing.T) {
	emptyPoly := &ScalarPolynomial{Coefs: []*secp256k1.ModNScalar{}}
	assert.Equal(t, scalarFromInt(0), emptyPoly.Eval(scalarFromInt(5)))
}

func TestPointPolynomialEmpty(t *testing.T) {
	emptyPoly := &PointPolynomial{Coefs: []*secp256k1.JacobianPoint{}}

	var zeroPoint secp256k1.JacobianPoint
	assert.True(t, PointEqual(emptyPoly.Eval(scalarFromInt(5)), &zeroPoint), "empty point polynomial should evaluate to zero")
}

func TestScalarPolynomialSingeton(t *testing.T) {
	singleton := []*ScalarEval{
		{X: scalarFromInt(5), Y: scalarFromInt(42)},
	}

	assert.Equal(t, scalarFromInt(42), ReconstructScalar(singleton), "single eval interpolation failed")
}

func TestPointPolynomialSingleton(t *testing.T) {
	height := pointFromScalar(scalarFromInt(42))
	singleton := []*PointEval{
		{X: scalarFromInt(5), Y: height},
	}

	assert.True(t, PointEqual(height, ReconstructPoint(singleton)), "single eval interpolation failed")
}

// Test Lagrange basis function
func TestLagrangeBasis(t *testing.T) {
	// Test with known x values
	xs := []*secp256k1.ModNScalar{
		scalarFromInt(1),
		scalarFromInt(2),
		scalarFromInt(3),
	}

	// Test L_0(0) for first basis polynomial
	// L_0(0) = (0-2)(0-3) / ((1-2)(1-3)) = 6/2 = 3
	basis0 := lagrangeBasisAt(xs, 0, scalarFromInt(0))
	expected0 := scalarFromInt(3)

	if !basis0.Equals(expected0) {
		t.Errorf("L_0(0) expected 3, got %s", basis0.String())
	}

	// Test L_1(0) for second basis polynomial
	// L_1(0) = (0-1)(0-3) / ((2-1)(2-3)) = 3/(-1) = -3
	basis1 := lagrangeBasisAt(xs, 1, scalarFromInt(0))
	expected1 := new(secp256k1.ModNScalar)
	expected1.NegateVal(scalarFromInt(3))

	if !basis1.Equals(expected1) {
		t.Errorf("L_1(0) expected -3, got %s", basis1.String())
	}

	// Test L_2(0) for third basis polynomial
	// L_2(0) = (0-1)(0-2) / ((3-1)(3-2)) = 2/2 = 1
	basis2 := lagrangeBasisAt(xs, 2, scalarFromInt(0))
	expected2 := scalarFromInt(1)

	if !basis2.Equals(expected2) {
		t.Errorf("L_2(0) expected 1, got %s", basis2.String())
	}

	// Verify that basis polynomials sum to 1 at x=0
	sum := new(secp256k1.ModNScalar)
	sum.Add(basis0).Add(basis1).Add(basis2)
	one := scalarFromInt(1)

	if !sum.Equals(one) {
		t.Errorf("Lagrange basis polynomials should sum to 1, got %s", sum.String())
	}
}

// Test consistency between scalar and point polynomials
func TestScalarPointConsistency(t *testing.T) {
	// Create matching scalar and point polynomials
	scalarCoefs := []*secp256k1.ModNScalar{
		scalarFromInt(10),
		scalarFromInt(20),
		scalarFromInt(30),
	}

	pointCoefs := make([]*secp256k1.JacobianPoint, len(scalarCoefs))
	for i, coef := range scalarCoefs {
		pointCoefs[i] = pointFromScalar(coef)
	}

	scalarPoly := &ScalarPolynomial{Coefs: scalarCoefs}
	pointPoly := &PointPolynomial{Coefs: pointCoefs}

	// Test that evaluations are consistent
	testPoints := []uint32{0, 1, 2, 5, 10}

	for _, xVal := range testPoints {
		x := scalarFromInt(xVal)

		scalarResult := scalarPoly.Eval(x)
		pointResult := pointPoly.Eval(x)
		expectedPoint := pointFromScalar(scalarResult)

		if !PointEqual(pointResult, expectedPoint) {
			t.Errorf("Inconsistency at x=%d between scalar and point polynomial", xVal)
		}
	}
}

// Test InterpolatingPointPolynomial construction from evaluations
func TestInterpolatingPointPolynomialFromEvals(t *testing.T) {
	// Create some test evaluation points
	evals := []*PointEval{
		{X: scalarFromInt(1), Y: pointFromScalar(scalarFromInt(10))},
		{X: scalarFromInt(2), Y: pointFromScalar(scalarFromInt(23))},
		{X: scalarFromInt(3), Y: pointFromScalar(scalarFromInt(40))},
	}

	poly := NewInterpolatingPointPolynomial(evals)

	// Test that the polynomial evaluates correctly at the original points
	for i, eval := range evals {
		result := poly.Eval(eval.X)
		if !PointEqual(result, eval.Y) {
			t.Errorf("Interpolating polynomial doesn't match evaluation point %d", i)
		}
	}

	// Test evaluation at a new point
	zero := scalarFromInt(0)
	secretPoint := poly.Eval(zero)

	// Verify using direct interpolation
	expectedSecret := InterpolatePoint(evals, zero)
	if !PointEqual(secretPoint, expectedSecret) {
		t.Errorf("Interpolating polynomial gives different result than direct interpolation")
	}
}

// Test InterpolatingPointPolynomial construction from PointPolynomial
func TestInterpolatingPointPolynomialFromPolynomial(t *testing.T) {
	// Create a specific polynomial: (5 + 3 x + 2 x^2) G
	originalPoly := &PointPolynomial{
		Coefs: []*secp256k1.JacobianPoint{
			pointFromScalar(scalarFromInt(5)),
			pointFromScalar(scalarFromInt(3)),
			pointFromScalar(scalarFromInt(2)),
		},
	}

	// Create InterpolatingPointPolynomial from it
	interpPoly := NewInterpolatingPointPolynomialFromPolynomial(originalPoly)

	// Test that both polynomials evaluate to the same result at various points
	testPoints := []uint32{0, 1, 2, 4, 10}
	for _, xVal := range testPoints {
		x := scalarFromInt(xVal)
		originalResult := originalPoly.Eval(x)
		interpResult := interpPoly.Eval(x)

		if !PointEqual(originalResult, interpResult) {
			t.Errorf("InterpolatingPointPolynomial differs from original at x=%d", xVal)
		}
	}
}

// Test InterpolatingPointPolynomial encoding and decoding
func TestInterpolatingPointPolynomialEncodeDecode(t *testing.T) {
	// Create test polynomial
	evals := []*PointEval{
		{X: scalarFromInt(1), Y: pointFromScalar(scalarFromInt(17))},
		{X: scalarFromInt(2), Y: pointFromScalar(scalarFromInt(31))},
		{X: scalarFromInt(3), Y: pointFromScalar(scalarFromInt(49))},
		{X: scalarFromInt(4), Y: pointFromScalar(scalarFromInt(71))},
	}

	originalPoly := NewInterpolatingPointPolynomial(evals)

	// Test encoding
	encoded := originalPoly.Encode()
	expectedLen := len(evals) * 64 // 64 bytes per point
	if len(encoded) != expectedLen {
		t.Errorf("Encoded length expected %d, got %d", expectedLen, len(encoded))
	}

	// Test decoding
	decodedPoly := encoded.Decode()

	// Test that original and decoded polynomials are equal
	if !originalPoly.Equal(decodedPoly) {
		t.Errorf("Decoded polynomial doesn't equal original")
	}

	// Test that they evaluate to the same results
	testPoints := []uint32{0, 1, 2, 5, 7}
	for _, xVal := range testPoints {
		x := scalarFromInt(xVal)
		originalResult := originalPoly.Eval(x)
		decodedResult := decodedPoly.Eval(x)

		if !PointEqual(originalResult, decodedResult) {
			t.Errorf("Decoded polynomial gives different result at x=%d", xVal)
		}
	}
}

// Test InterpolatingPointPolynomial equality
func TestInterpolatingPointPolynomialEquality(t *testing.T) {
	// Create two identical polynomials
	evals := []*PointEval{
		{X: scalarFromInt(1), Y: pointFromScalar(scalarFromInt(100))},
		{X: scalarFromInt(2), Y: pointFromScalar(scalarFromInt(200))},
	}

	poly1 := NewInterpolatingPointPolynomial(evals)
	poly2 := NewInterpolatingPointPolynomial(evals)

	// Test equality
	if !poly1.Equal(&poly2) {
		t.Errorf("Identical polynomials should be equal")
	}

	// Test reflexivity
	if !poly1.Equal(&poly1) {
		t.Errorf("Polynomial should be equal to itself")
	}

	// Create different polynomial
	differentEvals := []*PointEval{
		{X: scalarFromInt(1), Y: pointFromScalar(scalarFromInt(101))}, // Different value
		{X: scalarFromInt(2), Y: pointFromScalar(scalarFromInt(200))},
	}

	poly3 := NewInterpolatingPointPolynomial(differentEvals)

	// Test inequality
	if poly1.Equal(&poly3) {
		t.Errorf("Different polynomials should not be equal")
	}

	// Test different lengths
	shorterEvals := []*PointEval{
		{X: scalarFromInt(1), Y: pointFromScalar(scalarFromInt(100))},
	}

	poly4 := NewInterpolatingPointPolynomial(shorterEvals)

	if poly1.Equal(&poly4) {
		t.Errorf("Polynomials with different lengths should not be equal")
	}
}

// Test InterpolatingPointPolynomial construction from evaluations
func TestInterpolatingPointPolynomialWellDefined(t *testing.T) {
	// Create two evaluations of one polynomial
	p := &ScalarPolynomial{Coefs: []*secp256k1.ModNScalar{
		scalarFromInt(5),
		scalarFromInt(3),
		scalarFromInt(2),
	}}
	sourcePoly := p.ToPointPolynomial()

	evals1 := []*PointEval{
		{X: scalarFromInt(4), Y: sourcePoly.Eval(scalarFromInt(4))},
		{X: scalarFromInt(5), Y: sourcePoly.Eval(scalarFromInt(5))},
		{X: scalarFromInt(6), Y: sourcePoly.Eval(scalarFromInt(6))},
	}

	evals2 := []*PointEval{
		{X: scalarFromInt(7), Y: sourcePoly.Eval(scalarFromInt(7))},
		{X: scalarFromInt(8), Y: sourcePoly.Eval(scalarFromInt(8))},
		{X: scalarFromInt(9), Y: sourcePoly.Eval(scalarFromInt(9))},
	}

	poly1 := NewInterpolatingPointPolynomial(evals1)
	poly2 := NewInterpolatingPointPolynomial(evals2)

	// poly1ed := poly1.Encode().Decode()
	// poly2ed := poly2.Encode().Decode()

	if !poly1.Equal(&poly2) {
		t.Errorf("Interpolating polynomial for two evals of the same polynomial don't match")
	}
}

// Test InterpolatingPointPolynomial edge cases
func TestInterpolatingPointPolynomialEdgeCases(t *testing.T) {
	// Test no evaluation points (zero polynomial)
	zeroPoly := NewInterpolatingPointPolynomial([]*PointEval{})

	// Test single evaluation point (constant polynomial)
	singleEval := []*PointEval{
		{X: scalarFromInt(5), Y: pointFromScalar(scalarFromInt(42))},
	}

	constPoly := NewInterpolatingPointPolynomial(singleEval)

	// Should evaluate to the same point everywhere
	testPoints := []uint32{0, 1, 2, 10, 100}
	expectedZeroPoint := pointFromScalar(scalarFromInt(0))
	expectedConstPoint := pointFromScalar(scalarFromInt(42))

	for _, xVal := range testPoints {
		x := scalarFromInt(xVal)
		// result := constPoly.Eval(x)

		if !PointEqual(zeroPoly.Eval(x), expectedZeroPoint) {
			t.Errorf("Constant polynomial should return same value at x=%d", xVal)
		}

		if !PointEqual(constPoly.Eval(x), expectedConstPoint) {
			t.Errorf("Constant polynomial should return same value at x=%d", xVal)
		}
	}

	// Test encoding/decoding
	if !zeroPoly.Equal(zeroPoly.Encode().Decode()) {
		t.Errorf("Zero polynomial encode/decode failed")
	}

	if !constPoly.Equal(constPoly.Encode().Decode()) {
		t.Errorf("Single point polynomial encode/decode failed")
	}
}

// Test InterpolatingPointPolynomial consistency with direct interpolation
func TestInterpolatingPointPolynomialConsistency(t *testing.T) {
	// Create test evaluations
	evals := []*PointEval{
		{X: scalarFromInt(1), Y: pointFromScalar(scalarFromInt(7))},
		{X: scalarFromInt(3), Y: pointFromScalar(scalarFromInt(19))},
		{X: scalarFromInt(5), Y: pointFromScalar(scalarFromInt(37))},
		{X: scalarFromInt(7), Y: pointFromScalar(scalarFromInt(61))},
	}

	poly := NewInterpolatingPointPolynomial(evals)

	// Test that interpolating polynomial gives same results as direct interpolation
	testPoints := []uint32{0, 2, 4, 6, 8, 10}
	for _, xVal := range testPoints {
		x := scalarFromInt(xVal)
		polyResult := poly.Eval(x)
		directResult := InterpolatePoint(evals, x)

		if !PointEqual(polyResult, directResult) {
			t.Errorf("InterpolatingPointPolynomial inconsistent with direct interpolation at x=%d", xVal)
		}
	}
}
