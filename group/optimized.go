package group

import (
	"github.com/rafaelescrich/go-secp256k1/field"
	"github.com/rafaelescrich/go-secp256k1/scalar"
)

// Optimized point operations using uint64 field arithmetic
// These methods provide significant performance improvements over standard operations

// AddOptimized performs optimized point addition using uint64 field arithmetic.
// This provides significant performance improvements over the standard Add method.
func (p *Point) AddOptimized(a, b *Point) *Point {
	if a.infinity {
		*p = *b
		return p
	}
	if b.infinity {
		*p = *a
		return p
	}

	// Check if points are the same (use optimized field comparison)
	if a.x.Equal(b.x) {
		if a.y.Equal(b.y) {
			// Point doubling
			return p.DoubleOptimized(a)
		} else {
			// Points are inverses, result is point at infinity
			*p = *Infinity()
			return p
		}
	}

	// Use optimized field arithmetic for point addition
	// s = (by - ay) / (bx - ax)
	numerator := field.Zero()
	denominator := field.Zero()
	s := field.Zero()

	numerator.Sub(b.y, a.y)   // by - ay
	denominator.Sub(b.x, a.x) // bx - ax

	// For division, we still need to use big.Int for modular inverse
	// This is the main bottleneck, but field ops are now much faster
	denominatorBig := bigIntFromFieldVal(denominator)
	denominatorBig.ModInverse(denominatorBig, secp256k1Prime)
	denominatorInv, _ := fieldValFromBigInt(denominatorBig)

	s.MulUint64(numerator, denominatorInv) // Use optimized field multiplication

	// x3 = s² - ax - bx
	s2 := field.Zero()
	x3 := field.Zero()
	s2.MulUint64(s, s) // s² (optimized)
	x3.Sub(s2, a.x)    // s² - ax
	x3.Sub(x3, b.x)    // s² - ax - bx

	// y3 = s(ax - x3) - ay
	temp := field.Zero()
	y3 := field.Zero()
	temp.Sub(a.x, x3)     // ax - x3
	y3.MulUint64(s, temp) // s(ax - x3) (optimized)
	y3.Sub(y3, a.y)       // s(ax - x3) - ay

	p.x = x3
	p.y = y3
	p.infinity = false

	return p
}

// DoubleOptimized performs optimized point doubling using uint64 field arithmetic.
func (p *Point) DoubleOptimized(a *Point) *Point {
	if a.infinity {
		*p = *a
		return p
	}

	// Point doubling: s = (3*ax² + a) / (2*ay) where a=0 for secp256k1
	// s = 3*ax² / (2*ay)

	ax2 := field.Zero()
	three := field.Zero()
	threeBytes := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}
	three.SetBytes(threeBytes)

	numerator := field.Zero()
	denominator := field.Zero()
	s := field.Zero()

	ax2.MulUint64(a.x, a.x)         // ax² (optimized)
	numerator.MulUint64(three, ax2) // 3*ax² (optimized)

	denominator.AddUint64(a.y, a.y) // 2*ay (optimized)

	// For division, use big.Int for modular inverse
	denominatorBig := bigIntFromFieldVal(denominator)
	denominatorBig.ModInverse(denominatorBig, secp256k1Prime)
	denominatorInv, _ := fieldValFromBigInt(denominatorBig)

	s.MulUint64(numerator, denominatorInv) // Use optimized field multiplication

	// x3 = s² - 2*ax
	s2 := field.Zero()
	x3 := field.Zero()
	twoAx := field.Zero()

	s2.MulUint64(s, s)        // s² (optimized)
	twoAx.AddUint64(a.x, a.x) // 2*ax (optimized)
	x3.Sub(s2, twoAx)         // s² - 2*ax

	// y3 = s(ax - x3) - ay
	temp := field.Zero()
	y3 := field.Zero()
	temp.Sub(a.x, x3)     // ax - x3
	y3.MulUint64(s, temp) // s(ax - x3) (optimized)
	y3.Sub(y3, a.y)       // s(ax - x3) - ay

	p.x = x3
	p.y = y3
	p.infinity = false

	return p
}

// ScalarMultOptimized performs optimized scalar multiplication using uint64 arithmetic.
// This combines optimized field operations with windowed scalar multiplication.
func (p *Point) ScalarMultOptimized(k *scalar.Scalar, point *Point) *Point {
	if k.IsZero() || point.infinity {
		*p = *Infinity()
		return p
	}

	// Use binary method with optimized point operations
	kBytes := k.Bytes()
	*p = *Infinity()
	addend := &Point{}
	*addend = *point

	// Process bits from most significant to least significant
	for i := 0; i < 256; i++ {
		byteIndex := i / 8
		bitIndex := 7 - (i % 8)

		p.DoubleOptimized(p) // Use optimized doubling

		if (kBytes[byteIndex]>>bitIndex)&1 == 1 {
			p.AddOptimized(p, addend) // Use optimized addition
		}
	}

	return p
}
