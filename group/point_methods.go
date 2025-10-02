package group

import "github.com/rafaelescrich/go-secp256k1/field"

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
