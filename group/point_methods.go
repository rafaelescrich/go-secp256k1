package group

import (
	"math/big"

	"github.com/rafaelescrich/go-secp256k1/field"
)

// X returns the x-coordinate of the point.
func (p *Point) X() *field.FieldVal {
	if p.infinity {
		return field.Zero()
	}
	return p.x
}

// Y returns the y-coordinate of the point.
func (p *Point) Y() *field.FieldVal {
	if p.infinity {
		return field.Zero()
	}
	return p.y
}

// IsEven returns true if the y-coordinate is even (i.e., y mod 2 == 0).
func (p *Point) IsEven() bool {
	if p.infinity {
		return true // Point at infinity is considered even
	}
	// Check if the least significant bit of y is 0
	yBytes := p.y.Bytes()
	return (yBytes[31] & 1) == 0
}

// BytesUncompressed returns the uncompressed point encoding (64 bytes: X || Y).
func (p *Point) BytesUncompressed() []byte {
	if p.IsInfinity() {
		return make([]byte, 64)
	}
	result := make([]byte, 64)
	copy(result[:32], p.x.Bytes())
	copy(result[32:], p.y.Bytes())
	return result
}

// SetCompressed sets the point from a compressed x-coordinate and y parity.
func (p *Point) SetCompressed(xBytes []byte, oddY bool) bool {
	if len(xBytes) != 32 {
		return false
	}

	// Set x coordinate
	x := field.Zero()
	if !x.SetBytes(xBytes) {
		return false
	}

	// Compute y² = x³ + 7
	xBig := bigIntFromFieldVal(x)
	ySquared := new(big.Int).Mul(xBig, xBig)
	ySquared.Mul(ySquared, xBig)
	ySquared.Add(ySquared, secp256k1B)
	ySquared.Mod(ySquared, secp256k1Prime)

	// Compute y = sqrt(y²)
	y := new(big.Int).Exp(ySquared, secp256k1SqrtExp, secp256k1Prime)

	// Check if it's a valid square
	check := new(big.Int).Mul(y, y)
	check.Mod(check, secp256k1Prime)
	if check.Cmp(ySquared) != 0 {
		return false
	}

	// Ensure y has the correct parity
	yIsOdd := y.Bit(0) == 1
	if yIsOdd != oddY {
		y.Sub(secp256k1Prime, y)
	}

	yField, ok := fieldValFromBigInt(y)
	if !ok {
		return false
	}

	p.x = x
	p.y = yField
	p.infinity = false

	return p.IsOnCurve()
}

// SetXY sets the point from x and y coordinates directly.
func (p *Point) SetXY(x, y *field.FieldVal) {
	p.x = x
	p.y = y
	p.infinity = false
}
