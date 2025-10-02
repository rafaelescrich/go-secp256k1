package field

import "math/big"

// Inverse sets f = a^(-1) mod p and returns f.
func (f *FieldVal) Inverse(a *FieldVal) *FieldVal {
	if a.IsZero() {
		*f = *Zero()
		return f
	}

	inv := new(big.Int).ModInverse(a.bigInt(), fieldPrimeBig)
	if inv == nil {
		*f = *Zero()
		return f
	}

	f.fromBig(inv)
	return f
}

// Sqrt sets f = sqrt(a) mod p and returns f.
// Returns nil if a is not a quadratic residue.
func (f *FieldVal) Sqrt(a *FieldVal) *FieldVal {
	if a.IsZero() {
		*f = *Zero()
		return f
	}

	exp := new(big.Int).Add(fieldPrimeBig, big.NewInt(1))
	exp.Rsh(exp, 2)
	root := new(big.Int).Exp(a.bigInt(), exp, fieldPrimeBig)
	f.fromBig(root)

	check := Zero().Square(f)
	if !check.Equal(a) {
		return nil
	}

	return f
}
