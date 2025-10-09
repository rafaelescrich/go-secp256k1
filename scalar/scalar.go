// Package scalar implements arithmetic operations for secp256k1 scalar values.
// Scalars are integers modulo the curve order n.
package scalar

import (
	"crypto/subtle"
	"encoding/binary"
	"math/big"
	"math/bits"
)

// The secp256k1 curve order: n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
const (
	curveOrder0 = 0xD0364141
	curveOrder1 = 0xBFD25E8C
	curveOrder2 = 0xAF48A03B
	curveOrder3 = 0xBAAEDCE6
	curveOrder4 = 0xFFFFFFFE
	curveOrder5 = 0xFFFFFFFF
	curveOrder6 = 0xFFFFFFFF
	curveOrder7 = 0xFFFFFFFF
)

var (
	curveOrderBytes = []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
	}
	curveOrderBig = new(big.Int).SetBytes(curveOrderBytes)

	// Curve order as 4 uint64 limbs (little-endian) for optimized arithmetic
	curveOrderLimbs = [4]uint64{
		0xBFD25E8CD0364141, // n[0]
		0xBAAEDCE6AF48A03B, // n[1]
		0xFFFFFFFFFFFFFFFE, // n[2]
		0xFFFFFFFFFFFFFFFF, // n[3]
	}
)

// Scalar represents a scalar value as 8 32-bit limbs in little-endian order.
type Scalar struct {
	n [8]uint32
}

// Zero returns a scalar with value 0.
func Zero() *Scalar {
	return &Scalar{}
}

// One returns a scalar with value 1.
func One() *Scalar {
	one := &Scalar{}
	oneBytes := make([]byte, 32)
	oneBytes[31] = 1
	one.SetBytes(oneBytes)
	return one
}

// SetBytes sets the scalar to the value represented by the given
// 32-byte big-endian byte slice, reducing it modulo the curve order.
func (s *Scalar) SetBytes(b []byte) bool {
	if len(b) != 32 {
		return false
	}

	value := new(big.Int).SetBytes(b)
	value.Mod(value, curveOrderBig)
	bytes := padTo32(value.Bytes())
	for i := 0; i < 8; i++ {
		offset := 28 - i*4
		s.n[i] = binary.BigEndian.Uint32(bytes[offset : offset+4])
	}
	return true
}

// Bytes returns the scalar as a 32-byte big-endian byte slice.
func (s *Scalar) Bytes() []byte {
	b := make([]byte, 32)
	for i := 0; i < 8; i++ {
		offset := 28 - i*4
		binary.BigEndian.PutUint32(b[offset:offset+4], s.n[i])
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

func (s *Scalar) bigInt() *big.Int {
	return new(big.Int).SetBytes(s.Bytes())
}

func (s *Scalar) fromBig(v *big.Int) {
	if v == nil {
		*s = *Zero()
		return
	}
	res := new(big.Int).Mod(v, curveOrderBig)
	if res.Sign() < 0 {
		res.Add(res, curveOrderBig)
	}
	bytes := padTo32(res.Bytes())
	if !s.SetBytes(bytes) {
		*s = *Zero()
	}
}

// IsZero returns true if the scalar is zero.
func (s *Scalar) IsZero() bool {
	return s.n[0] == 0 && s.n[1] == 0 && s.n[2] == 0 && s.n[3] == 0 &&
		s.n[4] == 0 && s.n[5] == 0 && s.n[6] == 0 && s.n[7] == 0
}

// Equal returns true if the two scalars are equal.
func (s *Scalar) Equal(other *Scalar) bool {
	return subtle.ConstantTimeCompare(s.Bytes(), other.Bytes()) == 1
}

// SecureEqual performs a constant-time comparison of two scalars.
// This prevents timing attacks by ensuring the comparison takes the same time
// regardless of the values being compared.
func (s *Scalar) SecureEqual(other *Scalar) bool {
	return subtle.ConstantTimeCompare(s.Bytes(), other.Bytes()) == 1
}

// Clear securely clears the scalar from memory.
// This helps prevent memory dumps from revealing sensitive values.
func (s *Scalar) Clear() {
	for i := range s.n {
		s.n[i] = 0
	}
}

// Add sets s = a + b mod n and returns s.
func (s *Scalar) Add(a, b *Scalar) *Scalar {
	res := new(big.Int).Add(a.bigInt(), b.bigInt())
	res.Mod(res, curveOrderBig)
	s.fromBig(res)
	return s
}

// Sub sets s = a - b mod n and returns s.
func (s *Scalar) Sub(a, b *Scalar) *Scalar {
	res := new(big.Int).Sub(a.bigInt(), b.bigInt())
	res.Mod(res, curveOrderBig)
	if res.Sign() < 0 {
		res.Add(res, curveOrderBig)
	}
	s.fromBig(res)
	return s
}

// Mul sets s = a * b mod n and returns s.
func (s *Scalar) Mul(a, b *Scalar) *Scalar {
	res := new(big.Int).Mul(a.bigInt(), b.bigInt())
	res.Mod(res, curveOrderBig)
	s.fromBig(res)
	return s
}

// Square sets s = a^2 mod n and returns s.
func (s *Scalar) Square(a *Scalar) *Scalar {
	return s.Mul(a, a)
}

// Negate sets s = -a mod n and returns s.
func (s *Scalar) Negate(a *Scalar) *Scalar {
	if a.IsZero() {
		*s = *Zero()
		return s
	}

	res := new(big.Int).Neg(a.bigInt())
	res.Mod(res, curveOrderBig)
	if res.Sign() < 0 {
		res.Add(res, curveOrderBig)
	}
	s.fromBig(res)
	return s
}

// GetBits returns count bits starting at offset.
// This is used for windowing in scalar multiplication.
func (s *Scalar) GetBits(offset, count uint) uint32 {
	if count == 0 || count > 32 || offset >= 256 {
		return 0
	}

	limbIndex := offset / 32
	bitOffset := offset % 32

	if limbIndex >= 8 {
		return 0
	}

	// Extract bits from current limb
	result := s.n[limbIndex] >> bitOffset

	// If we need bits from the next limb
	if bitOffset+count > 32 && limbIndex+1 < 8 {
		bitsFromNext := count - (32 - bitOffset)
		nextBits := s.n[limbIndex+1] & ((1 << bitsFromNext) - 1)
		result |= nextBits << (32 - bitOffset)
	}

	// Mask to get only the requested number of bits
	mask := (uint32(1) << count) - 1
	return result & mask
}

// LessThan returns true if s < other.
func (s *Scalar) LessThan(other *Scalar) bool {
	// Compare from most significant limb to least significant
	for i := 7; i >= 0; i-- {
		if s.n[i] < other.n[i] {
			return true
		}
		if s.n[i] > other.n[i] {
			return false
		}
	}
	return false // Equal
}

// GreaterThan returns true if s > other.
func (s *Scalar) GreaterThan(other *Scalar) bool {
	return other.LessThan(s)
}

// LessThanOrEqual returns true if s <= other.
func (s *Scalar) LessThanOrEqual(other *Scalar) bool {
	return s.LessThan(other) || s.Equal(other)
}

// GreaterThanOrEqual returns true if s >= other.
func (s *Scalar) GreaterThanOrEqual(other *Scalar) bool {
	return s.GreaterThan(other) || s.Equal(other)
}

// IsLessThanOrder returns true if s < curve order.
func (s *Scalar) IsLessThanOrder() bool {
	return s.isLessThanOrder()
}

// isLessThanOrder returns true if s < curve order.
func (s *Scalar) isLessThanOrder() bool {
	// Compare with curve order from most significant limb
	for i := 7; i >= 0; i-- {
		var order uint32
		switch i {
		case 0:
			order = curveOrder0
		case 1:
			order = curveOrder1
		case 2:
			order = curveOrder2
		case 3:
			order = curveOrder3
		case 4:
			order = curveOrder4
		default:
			order = 0xFFFFFFFF
		}

		if s.n[i] > order {
			return false
		}
		if s.n[i] < order {
			return true
		}
	}
	return false // Equal to order, so not less than
}

// reduce reduces s modulo the curve order if s >= n.
func (s *Scalar) reduce() {
	if !s.isLessThanOrder() {
		s.subOrder()
	}
}

// subOrder subtracts the curve order from s.
func (s *Scalar) subOrder() {
	var borrow uint64

	// Subtract curve order
	diff := uint64(s.n[0]) - uint64(curveOrder0)
	s.n[0] = uint32(diff)
	borrow = (diff >> 32) & 1

	diff = uint64(s.n[1]) - uint64(curveOrder1) - borrow
	s.n[1] = uint32(diff)
	borrow = (diff >> 32) & 1

	diff = uint64(s.n[2]) - uint64(curveOrder2) - borrow
	s.n[2] = uint32(diff)
	borrow = (diff >> 32) & 1

	diff = uint64(s.n[3]) - uint64(curveOrder3) - borrow
	s.n[3] = uint32(diff)
	borrow = (diff >> 32) & 1

	diff = uint64(s.n[4]) - uint64(curveOrder4) - borrow
	s.n[4] = uint32(diff)
	borrow = (diff >> 32) & 1

	for i := 5; i < 8; i++ {
		diff = uint64(s.n[i]) - 0xFFFFFFFF - borrow
		s.n[i] = uint32(diff)
		borrow = (diff >> 32) & 1
	}
}

// addOrder adds the curve order to s.
func (s *Scalar) addOrder() {
	var carry uint64

	sum := uint64(s.n[0]) + uint64(curveOrder0)
	s.n[0] = uint32(sum)
	carry = sum >> 32

	sum = uint64(s.n[1]) + uint64(curveOrder1) + carry
	s.n[1] = uint32(sum)
	carry = sum >> 32

	sum = uint64(s.n[2]) + uint64(curveOrder2) + carry
	s.n[2] = uint32(sum)
	carry = sum >> 32

	sum = uint64(s.n[3]) + uint64(curveOrder3) + carry
	s.n[3] = uint32(sum)
	carry = sum >> 32

	sum = uint64(s.n[4]) + uint64(curveOrder4) + carry
	s.n[4] = uint32(sum)
	carry = sum >> 32

	for i := 5; i < 8; i++ {
		sum = uint64(s.n[i]) + 0xFFFFFFFF + carry
		s.n[i] = uint32(sum)
		carry = sum >> 32
	}
}

// reduceFrom512 reduces a 512-bit value to a scalar.
func (s *Scalar) reduceFrom512(val []uint32) {
	bigVal := new(big.Int)
	for i := 0; i < 16; i++ {
		if val[i] == 0 {
			continue
		}
		limb := new(big.Int).SetUint64(uint64(val[i]))
		limb.Lsh(limb, uint(32*i))
		bigVal.Add(bigVal, limb)
	}
	bigVal.Mod(bigVal, curveOrderBig)
	s.fromBig(bigVal)
}

// Helper functions for 512-bit arithmetic (simplified)
func (s *Scalar) isGreaterThan512(val []uint32) bool {
	// Check if val >= order (treating as 512-bit)
	// This is a simplified check
	for i := 15; i >= 8; i-- {
		if val[i] != 0 {
			return true
		}
	}

	// Check lower 8 limbs against order
	for i := 7; i >= 0; i-- {
		var order uint32
		switch i {
		case 0:
			order = curveOrder0
		case 1:
			order = curveOrder1
		case 2:
			order = curveOrder2
		case 3:
			order = curveOrder3
		case 4:
			order = curveOrder4
		default:
			order = 0xFFFFFFFF
		}

		if val[i] > order {
			return true
		}
		if val[i] < order {
			return false
		}
	}
	return false
}

func (s *Scalar) subtract512Order(val []uint32) {
	var borrow uint64

	// Subtract order from lower 8 limbs
	diff := uint64(val[0]) - uint64(curveOrder0)
	val[0] = uint32(diff)
	borrow = (diff >> 32) & 1

	diff = uint64(val[1]) - uint64(curveOrder1) - borrow
	val[1] = uint32(diff)
	borrow = (diff >> 32) & 1

	diff = uint64(val[2]) - uint64(curveOrder2) - borrow
	val[2] = uint32(diff)
	borrow = (diff >> 32) & 1

	diff = uint64(val[3]) - uint64(curveOrder3) - borrow
	val[3] = uint32(diff)
	borrow = (diff >> 32) & 1

	diff = uint64(val[4]) - uint64(curveOrder4) - borrow
	val[4] = uint32(diff)
	borrow = (diff >> 32) & 1

	for i := 5; i < 16; i++ {
		var order uint32
		if i < 8 {
			order = 0xFFFFFFFF
		} else {
			order = 0
		}

		diff = uint64(val[i]) - uint64(order) - borrow
		val[i] = uint32(diff)
		borrow = (diff >> 32) & 1
	}
}

// Optimized uint64-based arithmetic methods for better performance

// AddUint64 performs optimized scalar addition using uint64 arithmetic.
func (s *Scalar) AddUint64(a, b *Scalar) *Scalar {
	// Convert to uint64 limbs for faster arithmetic
	aLimbs := s.toUint64Limbs(a)
	bLimbs := s.toUint64Limbs(b)

	var carry uint64
	var result [4]uint64

	// Add limb by limb with carry propagation
	result[0], carry = bits.Add64(aLimbs[0], bLimbs[0], 0)
	result[1], carry = bits.Add64(aLimbs[1], bLimbs[1], carry)
	result[2], carry = bits.Add64(aLimbs[2], bLimbs[2], carry)
	result[3], carry = bits.Add64(aLimbs[3], bLimbs[3], carry)

	// If there's a carry or result >= n, subtract n
	if carry != 0 || s.greaterEqualOrderUint64(&result) {
		s.subOrderUint64(&result)
	}

	s.fromUint64Limbs(&result)
	return s
}

// MulUint64 performs optimized scalar multiplication using uint64 arithmetic.
func (s *Scalar) MulUint64(a, b *Scalar) *Scalar {
	aLimbs := s.toUint64Limbs(a)
	bLimbs := s.toUint64Limbs(b)

	// Multiply to get 512-bit result
	var t [8]uint64

	// School multiplication: multiply each limb of a by each limb of b
	for i := 0; i < 4; i++ {
		var carry uint64
		for j := 0; j < 4; j++ {
			// Multiply a[i] * b[j] and add to t[i+j], t[i+j+1]
			hi, lo := bits.Mul64(aLimbs[i], bLimbs[j])
			t[i+j], carry = bits.Add64(t[i+j], lo, carry)
			t[i+j+1], carry = bits.Add64(t[i+j+1], hi, carry)
		}
	}

	// Reduce 512-bit result modulo curve order
	s.reduce512Uint64(t)
	return s
}

// Helper methods for uint64 optimization

func (s *Scalar) toUint64Limbs(val *Scalar) [4]uint64 {
	return [4]uint64{
		uint64(val.n[0]) | uint64(val.n[1])<<32,
		uint64(val.n[2]) | uint64(val.n[3])<<32,
		uint64(val.n[4]) | uint64(val.n[5])<<32,
		uint64(val.n[6]) | uint64(val.n[7])<<32,
	}
}

func (s *Scalar) fromUint64Limbs(limbs *[4]uint64) {
	s.n[0] = uint32(limbs[0])
	s.n[1] = uint32(limbs[0] >> 32)
	s.n[2] = uint32(limbs[1])
	s.n[3] = uint32(limbs[1] >> 32)
	s.n[4] = uint32(limbs[2])
	s.n[5] = uint32(limbs[2] >> 32)
	s.n[6] = uint32(limbs[3])
	s.n[7] = uint32(limbs[3] >> 32)
}

func (s *Scalar) greaterEqualOrderUint64(limbs *[4]uint64) bool {
	// Compare from most significant limb to least significant
	for i := 3; i >= 0; i-- {
		if limbs[i] > curveOrderLimbs[i] {
			return true
		}
		if limbs[i] < curveOrderLimbs[i] {
			return false
		}
	}
	return true // Equal to order
}

func (s *Scalar) subOrderUint64(limbs *[4]uint64) {
	var borrow uint64
	limbs[0], borrow = bits.Sub64(limbs[0], curveOrderLimbs[0], 0)
	limbs[1], borrow = bits.Sub64(limbs[1], curveOrderLimbs[1], borrow)
	limbs[2], borrow = bits.Sub64(limbs[2], curveOrderLimbs[2], borrow)
	limbs[3], borrow = bits.Sub64(limbs[3], curveOrderLimbs[3], borrow)
}

func (s *Scalar) reduce512Uint64(t [8]uint64) {
	// Use hybrid approach: fast uint64 multiplication + big.Int reduction
	// Convert 512-bit result to big.Int for reduction
	bigVal := new(big.Int)

	// Build the big.Int efficiently
	bytes := make([]byte, 64) // 8 * 8 bytes
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(bytes[i*8:(i+1)*8], t[i])
	}

	// Convert little-endian bytes to big-endian for big.Int
	for i := 0; i < 32; i++ {
		bytes[i], bytes[63-i] = bytes[63-i], bytes[i]
	}

	bigVal.SetBytes(bytes)
	bigVal.Mod(bigVal, curveOrderBig)

	// Convert back efficiently
	s.fromBig(bigVal)
}
