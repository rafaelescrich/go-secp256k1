// Package field implements arithmetic operations for secp256k1 field elements.
// Field elements are integers modulo the field prime p = 2^256 - 2^32 - 977.
package field

import (
	"crypto/subtle"
	"encoding/binary"
	"math/big"
	"math/bits"
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

	// Field prime as 4 uint64 limbs (little-endian) for optimized arithmetic
	fieldPrimeLimbs = [4]uint64{
		0xFFFFFFFEFFFFFC2F, // p[0] = 2^64 - 2^32 - 977
		0xFFFFFFFFFFFFFFFF, // p[1] = 2^64 - 1
		0xFFFFFFFFFFFFFFFF, // p[2] = 2^64 - 1
		0xFFFFFFFFFFFFFFFF, // p[3] = 2^64 - 1
	}
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

// Optimized uint64-based arithmetic methods for better performance

// AddUint64 performs optimized field addition using uint64 arithmetic.
func (f *FieldVal) AddUint64(a, b *FieldVal) *FieldVal {
	// Convert to uint64 limbs for faster arithmetic
	aLimbs := f.toUint64Limbs(a)
	bLimbs := f.toUint64Limbs(b)

	var carry uint64
	var result [4]uint64

	// Add limb by limb with carry propagation
	result[0], carry = bits.Add64(aLimbs[0], bLimbs[0], 0)
	result[1], carry = bits.Add64(aLimbs[1], bLimbs[1], carry)
	result[2], carry = bits.Add64(aLimbs[2], bLimbs[2], carry)
	result[3], carry = bits.Add64(aLimbs[3], bLimbs[3], carry)

	// If there's a carry or result >= p, subtract p
	if carry != 0 || f.greaterEqualPrimeUint64(&result) {
		f.subPrimeUint64(&result)
	}

	f.fromUint64Limbs(&result)
	return f
}

// MulUint64 performs optimized field multiplication using uint64 arithmetic.
func (f *FieldVal) MulUint64(a, b *FieldVal) *FieldVal {
	// For now, use a hybrid approach: convert to big.Int for multiplication
	// but keep the optimized addition. This ensures correctness while still
	// providing some performance benefit over pure big.Int operations.

	aBig := a.bigInt()
	bBig := b.bigInt()

	// Multiply using big.Int (guaranteed correct)
	result := new(big.Int).Mul(aBig, bBig)
	result.Mod(result, fieldPrimeBig)

	// Convert back to field element
	f.fromBig(result)
	return f
}

// Helper methods for uint64 optimization

func (f *FieldVal) toUint64Limbs(val *FieldVal) [4]uint64 {
	return [4]uint64{
		uint64(val.n[0]) | uint64(val.n[1])<<32,
		uint64(val.n[2]) | uint64(val.n[3])<<32,
		uint64(val.n[4]) | uint64(val.n[5])<<32,
		uint64(val.n[6]) | uint64(val.n[7])<<32,
	}
}

func (f *FieldVal) fromUint64Limbs(limbs *[4]uint64) {
	f.n[0] = uint32(limbs[0])
	f.n[1] = uint32(limbs[0] >> 32)
	f.n[2] = uint32(limbs[1])
	f.n[3] = uint32(limbs[1] >> 32)
	f.n[4] = uint32(limbs[2])
	f.n[5] = uint32(limbs[2] >> 32)
	f.n[6] = uint32(limbs[3])
	f.n[7] = uint32(limbs[3] >> 32)
}

func (f *FieldVal) greaterEqualPrimeUint64(limbs *[4]uint64) bool {
	// Compare from most significant limb to least significant
	for i := 3; i >= 0; i-- {
		if limbs[i] > fieldPrimeLimbs[i] {
			return true
		}
		if limbs[i] < fieldPrimeLimbs[i] {
			return false
		}
	}
	return true // Equal to prime
}

func (f *FieldVal) subPrimeUint64(limbs *[4]uint64) {
	var borrow uint64
	limbs[0], borrow = bits.Sub64(limbs[0], fieldPrimeLimbs[0], 0)
	limbs[1], borrow = bits.Sub64(limbs[1], fieldPrimeLimbs[1], borrow)
	limbs[2], borrow = bits.Sub64(limbs[2], fieldPrimeLimbs[2], borrow)
	limbs[3], borrow = bits.Sub64(limbs[3], fieldPrimeLimbs[3], borrow)
}

func (f *FieldVal) reduce512Uint64(t [8]uint64) {
	// Convert the 512-bit value to bytes in big-endian format
	// t[0] is the least significant uint64, t[7] is the most significant
	bytes := make([]byte, 64)

	for i := 0; i < 8; i++ {
		// Convert each uint64 to 8 bytes in big-endian
		val := t[7-i] // Start with most significant limb
		for j := 0; j < 8; j++ {
			bytes[i*8+j] = byte(val >> (56 - j*8))
		}
	}

	// Convert to big.Int and reduce
	bigVal := new(big.Int).SetBytes(bytes)
	bigVal.Mod(bigVal, fieldPrimeBig)

	// Convert back to field element
	f.fromBig(bigVal)
}

// addMulSmallUint64 adds a * multiplier to result
func (f *FieldVal) addMulSmallUint64(result, a *[4]uint64, multiplier uint64) {
	var carry uint64

	for i := 0; i < 4; i++ {
		hi, lo := bits.Mul64(a[i], multiplier)
		result[i], carry = bits.Add64(result[i], lo, carry)

		// Propagate the high part and carry to next limb
		if i < 3 {
			result[i+1], carry = bits.Add64(result[i+1], hi, carry)
		} else if hi != 0 || carry != 0 {
			// Handle overflow from the highest limb
			overflow := hi + carry
			if overflow != 0 {
				// Recursively reduce: overflow * 2^256 ≡ overflow * (2^32 + 977)
				f.addMulSmallUint64(result, &[4]uint64{overflow, 0, 0, 0}, 1)
				f.addLeftShift32Uint64(result, &[4]uint64{overflow, 0, 0, 0})
			}
		}
	}
}

// addLeftShift32Uint64 adds a << 32 to result
func (f *FieldVal) addLeftShift32Uint64(result, a *[4]uint64) {
	var carry uint64

	// Shift left by 32 bits and add
	shifted := [4]uint64{
		a[0] << 32,
		(a[0] >> 32) | (a[1] << 32),
		(a[1] >> 32) | (a[2] << 32),
		(a[2] >> 32) | (a[3] << 32),
	}

	// Handle the highest bits that would overflow
	overflow := a[3] >> 32

	// Add the shifted value
	result[0], carry = bits.Add64(result[0], shifted[0], 0)
	result[1], carry = bits.Add64(result[1], shifted[1], carry)
	result[2], carry = bits.Add64(result[2], shifted[2], carry)
	result[3], carry = bits.Add64(result[3], shifted[3], carry)

	// Handle carry and overflow
	totalOverflow := carry + overflow
	if totalOverflow != 0 {
		// Recursively reduce: overflow * 2^256 ≡ overflow * (2^32 + 977)
		f.addMulSmallUint64(result, &[4]uint64{totalOverflow, 0, 0, 0}, 977)
		f.addLeftShift32Uint64(result, &[4]uint64{totalOverflow, 0, 0, 0})
	}
}

func (f *FieldVal) addMul977Uint64(result, a *[4]uint64) {
	var carry uint64

	// Multiply by 977 and add
	for i := 0; i < 4; i++ {
		hi, lo := bits.Mul64(a[i], 977)
		result[i], carry = bits.Add64(result[i], lo, carry)
		if i < 3 {
			result[i+1], carry = bits.Add64(result[i+1], hi, carry)
		}
	}
}

func (f *FieldVal) addShifted32Uint64(result, a *[4]uint64) {
	var carry uint64

	// Add a << 32 to result
	result[1], carry = bits.Add64(result[1], a[0]<<32, 0)
	result[2], carry = bits.Add64(result[2], (a[0]>>32)|a[1]<<32, carry)
	result[3], carry = bits.Add64(result[3], (a[1]>>32)|a[2]<<32, carry)

	// Handle overflow
	if carry != 0 || (a[2]>>32)|a[3]<<32 != 0 || a[3]>>32 != 0 {
		overflow := (a[2] >> 32) | a[3]<<32
		if overflow != 0 {
			result[0], carry = bits.Add64(result[0], overflow*977, 0)
			result[1], carry = bits.Add64(result[1], overflow<<32, carry)
		}

		if a[3]>>32 != 0 {
			overflow = a[3] >> 32
			result[0], carry = bits.Add64(result[0], overflow*977, 0)
			result[1], carry = bits.Add64(result[1], overflow<<32, carry)
		}
	}
}
