package scalar

import "math/big"

// Inverse sets s = a^(-1) mod n and returns s.
func (s *Scalar) Inverse(a *Scalar) *Scalar {
	if a.IsZero() {
		*s = *Zero()
		return s
	}

	inv := new(big.Int).ModInverse(a.bigInt(), curveOrderBig)
	if inv == nil {
		*s = *Zero()
		return s
	}

	s.fromBig(inv)
	return s
}
