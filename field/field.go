// Package field implements arithmetic operations for secp256k1 field elements.
// Field elements are integers modulo the field prime p = 2^256 - 2^32 - 977.
package field

import (
	"crypto/subtle"
	"encoding/binary"
	"math/big"
)

// The secp256k1 field prime: p = 2^256 - 2^32 - 977
// p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
const (
	fieldPrime0 = 0xFFFFFC2F
	fieldPrime1 = 0xFFFFFFFE
	fieldPrime2 = 0xFFFFFFFF
	fieldPrime3 = 0xFFFFFFFF
	fieldPrime4 = 0xFFFFFFFF
	fieldPrime5 = 0xFFFFFFFF
	fieldPrime6 = 0xFFFFFFFF
	fieldPrime7 = 0xFFFFFFFF
)

var (
	fieldPrimeBytes = []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
	}
	fieldPrimeBig = new(big.Int).SetBytes(fieldPrimeBytes)
)

// FieldVal represents a field element as 8 32-bit limbs in little-endian order.
// This representation allows for efficient arithmetic operations.
type FieldVal struct {
	n [8]uint32
}

// Zero returns a field element with value 0.
func Zero() *FieldVal {
	return &FieldVal{}
}

// One returns a field element with value 1.
func One() *FieldVal {
	one := &FieldVal{}
	oneBytes := make([]byte, 32)
	oneBytes[31] = 1
	one.SetBytes(oneBytes)
	return one
}

// SetBytes sets the field element to the value represented by the given
// 32-byte big-endian byte slice, reducing it modulo the field prime.
func (f *FieldVal) SetBytes(b []byte) bool {
	if len(b) != 32 {
		return false
	}

	value := new(big.Int).SetBytes(b)
	value.Mod(value, fieldPrimeBig)
	bytes := padTo32(value.Bytes())
	for i := 0; i < 8; i++ {
		offset := 28 - i*4
		f.n[i] = binary.BigEndian.Uint32(bytes[offset : offset+4])
	}
	return true
}

// Bytes returns the field element as a 32-byte big-endian byte slice.
func (f *FieldVal) Bytes() []byte {
	b := make([]byte, 32)
	for i := 0; i < 8; i++ {
		offset := 28 - i*4
		binary.BigEndian.PutUint32(b[offset:offset+4], f.n[i])
	}
	return b
}

func padTo32(b []byte) []byte {
	if len(b) > 32 {
		b = b[len(b)-32:]
	}
	if len(b) == 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func (f *FieldVal) bigInt() *big.Int {
	return new(big.Int).SetBytes(f.Bytes())
}

func (f *FieldVal) fromBig(v *big.Int) {
	if v == nil {
		*f = *Zero()
		return
	}
	res := new(big.Int).Mod(v, fieldPrimeBig)
	if res.Sign() < 0 {
		res.Add(res, fieldPrimeBig)
	}
	bytes := padTo32(res.Bytes())
	if !f.SetBytes(bytes) {
		*f = *Zero()
	}
}

// IsZero returns true if the field element is zero.
func (f *FieldVal) IsZero() bool {
	return f.n[0] == 0 && f.n[1] == 0 && f.n[2] == 0 && f.n[3] == 0 &&
		f.n[4] == 0 && f.n[5] == 0 && f.n[6] == 0 && f.n[7] == 0
}

// Equal returns true if the two field elements are equal.
func (f *FieldVal) Equal(other *FieldVal) bool {
	return subtle.ConstantTimeCompare(f.Bytes(), other.Bytes()) == 1
}

// Add sets f = a + b mod p and returns f.
func (f *FieldVal) Add(a, b *FieldVal) *FieldVal {
	res := new(big.Int).Add(a.bigInt(), b.bigInt())
	res.Mod(res, fieldPrimeBig)
	f.fromBig(res)
	return f
}

// Sub sets f = a - b mod p and returns f.
func (f *FieldVal) Sub(a, b *FieldVal) *FieldVal {
	res := new(big.Int).Sub(a.bigInt(), b.bigInt())
	res.Mod(res, fieldPrimeBig)
	if res.Sign() < 0 {
		res.Add(res, fieldPrimeBig)
	}
	f.fromBig(res)
	return f
}

// Mul sets f = a * b mod p and returns f.
func (f *FieldVal) Mul(a, b *FieldVal) *FieldVal {
	res := new(big.Int).Mul(a.bigInt(), b.bigInt())
	res.Mod(res, fieldPrimeBig)
	f.fromBig(res)
	return f
}

// Square sets f = a^2 mod p and returns f.
func (f *FieldVal) Square(a *FieldVal) *FieldVal {
	return f.Mul(a, a)
}

// Negate sets f = -a mod p and returns f.
func (f *FieldVal) Negate(a *FieldVal) *FieldVal {
	if a.IsZero() {
		*f = *Zero()
		return f
	}

	res := new(big.Int).Neg(a.bigInt())
	res.Mod(res, fieldPrimeBig)
	if res.Sign() < 0 {
		res.Add(res, fieldPrimeBig)
	}
	f.fromBig(res)
	return f
}

// isLessThanPrime returns true if f < field prime.
func (f *FieldVal) isLessThanPrime() bool {
	// Compare with field prime from most significant limb
	for i := 7; i >= 0; i-- {
		var prime uint32
		switch i {
		case 0:
			prime = fieldPrime0
		case 1:
			prime = fieldPrime1
		default:
			prime = 0xFFFFFFFF
		}

		if f.n[i] > prime {
			return false
		}
		if f.n[i] < prime {
			return true
		}
	}
	return false // Equal to prime, so not less than
}

// reduce reduces f modulo the field prime if f >= p.
func (f *FieldVal) reduce() {
	if !f.isLessThanPrime() {
		f.subPrime()
	}
}

// subPrime subtracts the field prime from f.
func (f *FieldVal) subPrime() {
	var borrow uint64

	// Subtract field prime
	diff := uint64(f.n[0]) - uint64(fieldPrime0)
	f.n[0] = uint32(diff)
	borrow = (diff >> 32) & 1

	diff = uint64(f.n[1]) - uint64(fieldPrime1) - borrow
	f.n[1] = uint32(diff)
	borrow = (diff >> 32) & 1

	for i := 2; i < 8; i++ {
		diff = uint64(f.n[i]) - 0xFFFFFFFF - borrow
		f.n[i] = uint32(diff)
		borrow = (diff >> 32) & 1
	}
}

// addPrime adds the field prime to f.
func (f *FieldVal) addPrime() {
	var carry uint64

	sum := uint64(f.n[0]) + uint64(fieldPrime0)
	f.n[0] = uint32(sum)
	carry = sum >> 32

	sum = uint64(f.n[1]) + uint64(fieldPrime1) + carry
	f.n[1] = uint32(sum)
	carry = sum >> 32

	for i := 2; i < 8; i++ {
		sum = uint64(f.n[i]) + 0xFFFFFFFF + carry
		f.n[i] = uint32(sum)
		carry = sum >> 32
	}
}

// reduceFrom512 reduces a 512-bit value to a field element.
func (f *FieldVal) reduceFrom512(val []uint32) {
	bigVal := new(big.Int)
	for i := 0; i < 16; i++ {
		if val[i] == 0 {
			continue
		}
		limb := new(big.Int).SetUint64(uint64(val[i]))
		limb.Lsh(limb, uint(32*i))
		bigVal.Add(bigVal, limb)
	}
	bigVal.Mod(bigVal, fieldPrimeBig)
	f.fromBig(bigVal)
}
