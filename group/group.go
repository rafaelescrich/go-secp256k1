// Package group implements elliptic curve group operations for secp256k1.
// The secp256k1 curve is defined by y² = x³ + 7 over the field Fp.
package group

import (
	"math/big"

	"github.com/rafaelescrich/go-secp256k1/field"
	"github.com/rafaelescrich/go-secp256k1/scalar"
)

var (
	secp256k1Prime = new(big.Int).SetBytes([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
	})
	secp256k1B       = big.NewInt(7)
	secp256k1SqrtExp = new(big.Int).Rsh(new(big.Int).Add(secp256k1Prime, big.NewInt(1)), 2)
	twoBig           = big.NewInt(2)
	threeBig         = big.NewInt(3)
)

func bigIntFromFieldVal(v *field.FieldVal) *big.Int {
	if v == nil {
		return big.NewInt(0)
	}
	return new(big.Int).SetBytes(v.Bytes())
}

func fieldValFromBigInt(i *big.Int) (*field.FieldVal, bool) {
	if i == nil {
		return nil, false
	}
	v := new(big.Int).Mod(new(big.Int).Set(i), secp256k1Prime)
	if v.Sign() < 0 {
		v.Add(v, secp256k1Prime)
	}

	bytes := padTo32(v.Bytes())
	f := field.Zero()
	if !f.SetBytes(bytes) {
		return nil, false
	}
	return f, true
}

func padTo32(b []byte) []byte {
	if len(b) > 32 {
		// trim leading zeros if present
		b = b[len(b)-32:]
	}
	if len(b) == 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// Point represents a point on the secp256k1 curve in affine coordinates (x, y).
type Point struct {
	x, y     *field.FieldVal
	infinity bool
}

// JacobianPoint represents a point in Jacobian coordinates (X, Y, Z).
// The affine coordinates are (X/Z², Y/Z³).
type JacobianPoint struct {
	x, y, z *field.FieldVal
}

// NewPoint creates a new point with the given affine coordinates.
func NewPoint(x, y *field.FieldVal) *Point {
	return &Point{
		x:        x,
		y:        y,
		infinity: false,
	}
}

// NewJacobianPoint creates a new point with the given Jacobian coordinates.
func NewJacobianPoint(x, y, z *field.FieldVal) *JacobianPoint {
	return &JacobianPoint{
		x: x,
		y: y,
		z: z,
	}
}

// Infinity returns the point at infinity.
func Infinity() *Point {
	return &Point{
		x:        field.Zero(),
		y:        field.Zero(),
		infinity: true,
	}
}

// JacobianInfinity returns the point at infinity in Jacobian coordinates.
func JacobianInfinity() *JacobianPoint {
	return &JacobianPoint{
		x: field.One(),
		y: field.One(),
		z: field.Zero(),
	}
}

// Generator returns the secp256k1 generator point G.
func Generator() *Point {
	// G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
	//      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

	gx := field.Zero()
	gy := field.Zero()

	gxBytes := []byte{
		0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
		0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
		0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
		0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
	}

	gyBytes := []byte{
		0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
		0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
		0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
		0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
	}

	gx.SetBytes(gxBytes)
	gy.SetBytes(gyBytes)

	return NewPoint(gx, gy)
}

// IsInfinity returns true if the point is the point at infinity.
func (p *Point) IsInfinity() bool {
	return p.infinity
}

// IsOnCurve returns true if the point is on the secp256k1 curve.
func (p *Point) IsOnCurve() bool {
	if p.infinity {
		return true
	}

	x := bigIntFromFieldVal(p.x)
	y := bigIntFromFieldVal(p.y)

	if x.Cmp(secp256k1Prime) >= 0 || y.Cmp(secp256k1Prime) >= 0 {
		return false
	}

	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, secp256k1Prime)

	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, secp256k1B)
	rhs.Mod(rhs, secp256k1Prime)

	return lhs.Cmp(rhs) == 0
}

// Equal returns true if the two points are equal.
func (p *Point) Equal(other *Point) bool {
	if p.infinity && other.infinity {
		return true
	}
	if p.infinity || other.infinity {
		return false
	}
	return p.x.Equal(other.x) && p.y.Equal(other.y)
}

// Add sets p = a + b and returns p.
func (p *Point) Add(a, b *Point) *Point {
	if a.infinity {
		*p = *b
		return p
	}
	if b.infinity {
		*p = *a
		return p
	}

	bigA, ok := pointToBigAffine(a)
	if !ok {
		*p = *Infinity()
		return p
	}
	bigB, ok := pointToBigAffine(b)
	if !ok {
		*p = *Infinity()
		return p
	}

	sum := affineAddBig(bigA, bigB)
	converted, ok := bigAffineToPoint(sum)
	if !ok {
		*p = *Infinity()
		return p
	}

	*p = *converted
	return p
}

// Double sets p = 2*a and returns p.
func (p *Point) Double(a *Point) *Point {
	if a.infinity {
		*p = *a
		return p
	}

	bigA, ok := pointToBigAffine(a)
	if !ok {
		*p = *Infinity()
		return p
	}

	doubled := affineDoubleBig(bigA)
	converted, ok := bigAffineToPoint(doubled)
	if !ok {
		*p = *Infinity()
		return p
	}

	*p = *converted
	return p
}

// ScalarMult sets p = k*a and returns p.
func (p *Point) ScalarMult(k *scalar.Scalar, a *Point) *Point {
	if a.infinity || k.IsZero() {
		*p = *Infinity()
		return p
	}

	base, ok := pointToBigAffine(a)
	if !ok {
		*p = *Infinity()
		return p
	}

	result := scalarMultiplyAffine(base, scalarToBigInt(k))
	if result.infinity {
		*p = *Infinity()
		return p
	}

	converted, ok := bigAffineToPoint(result)
	if !ok {
		*p = *Infinity()
		return p
	}

	*p = *converted
	return p
}

// FromJacobian converts a Jacobian point to affine coordinates.
func (p *Point) FromJacobian(jp *JacobianPoint) *Point {
	if jp.z.IsZero() {
		*p = *Infinity()
		return p
	}

	// Compute z^(-1)
	zInv := field.Zero().Inverse(jp.z)
	zInv2 := field.Zero().Square(zInv)
	zInv3 := field.Zero().Mul(zInv2, zInv)

	// Convert: x = X/Z², y = Y/Z³
	p.x = field.Zero().Mul(jp.x, zInv2)
	p.y = field.Zero().Mul(jp.y, zInv3)
	p.infinity = false

	return p
}

// Add sets jp = a + b and returns jp (Jacobian coordinates).
func (jp *JacobianPoint) Add(a, b *JacobianPoint) *JacobianPoint {
	// Handle special cases
	if a.z.IsZero() {
		*jp = *b
		return jp
	}
	if b.z.IsZero() {
		*jp = *a
		return jp
	}

	// Use the unified addition formula for Jacobian coordinates
	// This handles both addition and doubling cases

	z1z1 := field.Zero().Square(a.z)
	z2z2 := field.Zero().Square(b.z)
	u1 := field.Zero().Mul(a.x, z2z2)
	u2 := field.Zero().Mul(b.x, z1z1)
	s1 := field.Zero().Mul(a.y, b.z).Mul(field.Zero(), z2z2)
	s2 := field.Zero().Mul(b.y, a.z).Mul(field.Zero(), z1z1)

	if u1.Equal(u2) {
		if s1.Equal(s2) {
			// Point doubling case
			return jp.Double(a)
		} else {
			// Points are inverses, result is infinity
			*jp = *JacobianInfinity()
			return jp
		}
	}

	h := field.Zero().Sub(u2, u1)
	i := field.Zero().Square(field.Zero().Add(h, h))
	j := field.Zero().Mul(h, i)
	r := field.Zero().Sub(s2, s1).Add(field.Zero(), field.Zero())
	v := field.Zero().Mul(u1, i)

	jp.x = field.Zero().Square(r).Sub(field.Zero(), j).Sub(field.Zero(), v).Sub(field.Zero(), v)
	jp.y = field.Zero().Sub(v, jp.x).Mul(field.Zero(), r).Sub(field.Zero(), field.Zero().Mul(s1, j))
	jp.z = field.Zero().Add(a.z, b.z).Square(field.Zero()).Sub(field.Zero(), z1z1).Sub(field.Zero(), z2z2).Mul(field.Zero(), h)

	return jp
}

// Double sets jp = 2*a and returns jp (Jacobian coordinates).
func (jp *JacobianPoint) Double(a *JacobianPoint) *JacobianPoint {
	if a.z.IsZero() {
		*jp = *a
		return jp
	}

	// Point doubling in Jacobian coordinates
	// Using the formula optimized for a = 0 (secp256k1 has a = 0)

	y1y1 := field.Zero().Square(a.y)
	s := field.Zero().Mul(a.x, y1y1).Add(field.Zero(), field.Zero()).Add(field.Zero(), field.Zero())
	m := field.Zero().Square(a.x).Add(field.Zero(), field.Zero()).Add(field.Zero(), field.Zero())

	jp.x = field.Zero().Square(m).Sub(field.Zero(), s).Sub(field.Zero(), s)
	jp.y = field.Zero().Sub(s, jp.x).Mul(field.Zero(), m).Sub(field.Zero(), field.Zero().Square(y1y1).Add(field.Zero(), field.Zero()).Add(field.Zero(), field.Zero()).Add(field.Zero(), field.Zero()))
	jp.z = field.Zero().Mul(a.y, a.z).Add(field.Zero(), field.Zero())

	return jp
}

// ScalarMult sets jp = k*a and returns jp (Jacobian coordinates).
func (jp *JacobianPoint) ScalarMult(k *scalar.Scalar, a *JacobianPoint) *JacobianPoint {
	if k.IsZero() || a.z.IsZero() {
		*jp = *JacobianInfinity()
		return jp
	}

	// Use binary method (double-and-add)
	// Start from the most significant bit
	*jp = *JacobianInfinity()
	temp := &JacobianPoint{}
	*temp = *a

	// Process each bit of the scalar
	for i := 255; i >= 0; i-- {
		jp.Double(jp)

		bit := k.GetBits(uint(i), 1)
		if bit == 1 {
			jp.Add(jp, temp)
		}
	}

	return jp
}

// Negate sets p = -a and returns p.
func (p *Point) Negate(a *Point) *Point {
	if a.infinity {
		*p = *a
		return p
	}

	p.x = a.x
	p.y = field.Zero().Negate(a.y)
	p.infinity = false

	return p
}

// Bytes returns the compressed encoding of the point (33 bytes).
func (p *Point) Bytes() []byte {
	if p.infinity {
		return make([]byte, 33) // All zeros for point at infinity
	}

	result := make([]byte, 33)
	xBytes := p.x.Bytes()
	copy(result[1:], xBytes)

	// Set the compression flag based on y coordinate parity
	yBytes := p.y.Bytes()
	if yBytes[31]&1 == 1 {
		result[0] = 0x03 // Odd y
	} else {
		result[0] = 0x02 // Even y
	}

	return result
}

// SetBytes sets the point from a compressed encoding (33 bytes).
func (p *Point) SetBytes(b []byte) bool {
	if len(b) != 33 {
		return false
	}

	if b[0] == 0x00 {
		// Point at infinity
		*p = *Infinity()
		return true
	}

	if b[0] != 0x02 && b[0] != 0x03 {
		return false
	}

	x := new(big.Int).SetBytes(b[1:])
	if x.Cmp(secp256k1Prime) >= 0 {
		return false
	}

	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, secp256k1B)
	rhs.Mod(rhs, secp256k1Prime)

	y := new(big.Int).Exp(rhs, secp256k1SqrtExp, secp256k1Prime)
	check := new(big.Int).Mul(y, y)
	check.Mod(check, secp256k1Prime)
	if check.Cmp(rhs) != 0 {
		return false
	}

	if uint(y.Bit(0)) != uint(b[0]&1) {
		y.Sub(secp256k1Prime, y)
	}

	xField, ok := fieldValFromBigInt(x)
	if !ok {
		return false
	}

	yField, ok := fieldValFromBigInt(y)
	if !ok {
		return false
	}

	p.x = xField
	p.y = yField
	p.infinity = false
	return true
}

type bigAffinePoint struct {
	x, y     *big.Int
	infinity bool
}

func scalarToBigInt(k *scalar.Scalar) *big.Int {
	if k == nil {
		return big.NewInt(0)
	}
	return new(big.Int).SetBytes(k.Bytes())
}

func pointToBigAffine(p *Point) (*bigAffinePoint, bool) {
	if p == nil {
		return nil, false
	}
	if p.infinity {
		return &bigAffinePoint{infinity: true}, true
	}
	if !p.IsOnCurve() {
		return nil, false
	}

	return &bigAffinePoint{
		x: bigIntFromFieldVal(p.x),
		y: bigIntFromFieldVal(p.y),
	}, true
}

func bigAffineToPoint(bp *bigAffinePoint) (*Point, bool) {
	if bp.infinity {
		return Infinity(), true
	}

	xField, ok := fieldValFromBigInt(bp.x)
	if !ok {
		return nil, false
	}

	yField, ok := fieldValFromBigInt(bp.y)
	if !ok {
		return nil, false
	}

	return &Point{x: xField, y: yField, infinity: false}, true
}

func modAddBig(a, b *big.Int) *big.Int {
	sum := new(big.Int).Add(a, b)
	sum.Mod(sum, secp256k1Prime)
	return sum
}

func modSubBig(a, b *big.Int) *big.Int {
	diff := new(big.Int).Sub(a, b)
	diff.Mod(diff, secp256k1Prime)
	if diff.Sign() < 0 {
		diff.Add(diff, secp256k1Prime)
	}
	return diff
}

func modMulBig(a, b *big.Int) *big.Int {
	prod := new(big.Int).Mul(a, b)
	prod.Mod(prod, secp256k1Prime)
	return prod
}

func modInvBig(a *big.Int) *big.Int {
	inv := new(big.Int).ModInverse(a, secp256k1Prime)
	if inv == nil {
		return big.NewInt(0)
	}
	return inv
}

func affineAddBig(a, b *bigAffinePoint) *bigAffinePoint {
	if a.infinity {
		return b.copy()
	}
	if b.infinity {
		return a.copy()
	}

	if a.x.Cmp(b.x) == 0 {
		sumY := modAddBig(a.y, b.y)
		if sumY.Sign() == 0 {
			return &bigAffinePoint{infinity: true}
		}
		return affineDoubleBig(a)
	}

	numerator := modSubBig(b.y, a.y)
	denominator := modSubBig(b.x, a.x)
	inv := modInvBig(denominator)
	if inv.Sign() == 0 {
		return &bigAffinePoint{infinity: true}
	}
	lambda := modMulBig(numerator, inv)
	lambdaSq := modMulBig(lambda, lambda)
	xr := modSubBig(modSubBig(lambdaSq, a.x), b.x)
	yr := modSubBig(modMulBig(lambda, modSubBig(a.x, xr)), a.y)
	return &bigAffinePoint{x: xr, y: yr}
}

func affineDoubleBig(p *bigAffinePoint) *bigAffinePoint {
	if p.infinity || p.y.Sign() == 0 {
		return &bigAffinePoint{infinity: true}
	}

	xSq := modMulBig(p.x, p.x)
	threeXSq := modMulBig(threeBig, xSq)
	twoY := modMulBig(twoBig, p.y)
	inv := modInvBig(twoY)
	if inv.Sign() == 0 {
		return &bigAffinePoint{infinity: true}
	}
	lambda := modMulBig(threeXSq, inv)
	lambdaSq := modMulBig(lambda, lambda)
	twoX := modMulBig(twoBig, p.x)
	xr := modSubBig(lambdaSq, twoX)
	yr := modSubBig(modMulBig(lambda, modSubBig(p.x, xr)), p.y)
	return &bigAffinePoint{x: xr, y: yr}
}

func (p *bigAffinePoint) copy() *bigAffinePoint {
	if p.infinity {
		return &bigAffinePoint{infinity: true}
	}
	return &bigAffinePoint{x: new(big.Int).Set(p.x), y: new(big.Int).Set(p.y)}
}

func scalarMultiplyAffine(p *bigAffinePoint, k *big.Int) *bigAffinePoint {
	if k.Sign() == 0 || p.infinity {
		return &bigAffinePoint{infinity: true}
	}

	result := &bigAffinePoint{infinity: true}
	addend := p.copy()

	for i := k.BitLen() - 1; i >= 0; i-- {
		result = affineDoubleBig(result)
		if k.Bit(i) == 1 {
			result = affineAddBig(result, addend)
		}
	}

	return result
}
