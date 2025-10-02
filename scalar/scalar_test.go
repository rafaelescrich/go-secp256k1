package scalar

import (
	"bytes"
	"testing"
)

func TestScalarBasicOperations(t *testing.T) {
	// Test zero and one
	zero := Zero()
	one := One()

	if !zero.IsZero() {
		t.Error("Zero() should return zero")
	}

	if one.IsZero() {
		t.Error("One() should not return zero")
	}

	// Test addition: 0 + 1 = 1
	result := Zero().Add(zero, one)
	if !result.Equal(one) {
		t.Error("0 + 1 should equal 1")
	}

	// Test subtraction: 1 - 1 = 0
	result = Zero().Sub(one, one)
	if !result.IsZero() {
		t.Error("1 - 1 should equal 0")
	}

	// Test multiplication: 1 * 1 = 1
	result = Zero().Mul(one, one)
	if !result.Equal(one) {
		t.Error("1 * 1 should equal 1")
	}
}

func TestScalarSetBytes(t *testing.T) {
	// Test setting from valid bytes
	validBytes := make([]byte, 32)
	validBytes[31] = 1 // Set to 1

	s := Zero()
	if !s.SetBytes(validBytes) {
		t.Error("SetBytes should succeed for valid input")
	}

	// Test that bytes round-trip correctly
	resultBytes := s.Bytes()
	if !bytes.Equal(validBytes, resultBytes) {
		t.Error("Bytes should round-trip correctly")
	}

	// Test invalid length
	invalidBytes := make([]byte, 31)
	if s.SetBytes(invalidBytes) {
		t.Error("SetBytes should fail for invalid length")
	}
}

func TestScalarArithmetic(t *testing.T) {
	// Test with some known values
	a := Zero()
	b := Zero()
	
	// Set a = 2
	aBytes := make([]byte, 32)
	aBytes[31] = 2
	a.SetBytes(aBytes)
	
	// Set b = 3
	bBytes := make([]byte, 32)
	bBytes[31] = 3
	b.SetBytes(bBytes)

	// Test addition: 2 + 3 = 5
	result := Zero().Add(a, b)
	expected := Zero()
	expectedBytes := make([]byte, 32)
	expectedBytes[31] = 5
	expected.SetBytes(expectedBytes)
	
	if !result.Equal(expected) {
		t.Error("2 + 3 should equal 5")
	}

	// Test multiplication: 2 * 3 = 6
	result = Zero().Mul(a, b)
	expectedBytes[31] = 6
	expected.SetBytes(expectedBytes)
	
	if !result.Equal(expected) {
		t.Error("2 * 3 should equal 6")
	}

	// Test squaring: 3^2 = 9
	result = Zero().Square(b)
	expectedBytes[31] = 9
	expected.SetBytes(expectedBytes)
	
	if !result.Equal(expected) {
		t.Error("3^2 should equal 9")
	}
}

func TestScalarNegation(t *testing.T) {
	// Test negation of zero
	zero := Zero()
	negZero := Zero().Negate(zero)
	if !negZero.IsZero() {
		t.Error("Negation of zero should be zero")
	}

	// Test double negation
	one := One()
	negOne := Zero().Negate(one)
	doubleNeg := Zero().Negate(negOne)
	
	if !doubleNeg.Equal(one) {
		t.Error("Double negation should return original value")
	}

	// Test that a + (-a) = 0
	sum := Zero().Add(one, negOne)
	if !sum.IsZero() {
		t.Error("a + (-a) should equal zero")
	}
}

func TestScalarInverse(t *testing.T) {
	// Test inverse of one
	one := One()
	invOne := Zero().Inverse(one)
	if !invOne.Equal(one) {
		t.Error("Inverse of 1 should be 1")
	}

	// Test that a * a^(-1) = 1 for non-zero a
	a := Zero()
	aBytes := make([]byte, 32)
	aBytes[31] = 7
	a.SetBytes(aBytes)
	
	invA := Zero().Inverse(a)
	product := Zero().Mul(a, invA)
	
	if !product.Equal(one) {
		t.Error("a * a^(-1) should equal 1")
	}
}

func TestScalarGetBits(t *testing.T) {
	// Test bit extraction
	s := Zero()
	sBytes := make([]byte, 32)
	sBytes[31] = 0xFF // Set lowest byte to all 1s
	s.SetBytes(sBytes)

	// Get the lowest 8 bits
	bits := s.GetBits(0, 8)
	if bits != 0xFF {
		t.Errorf("Expected 0xFF, got 0x%X", bits)
	}

	// Get 4 bits starting at offset 4
	bits = s.GetBits(4, 4)
	if bits != 0x0F {
		t.Errorf("Expected 0x0F, got 0x%X", bits)
	}

	// Test edge cases
	bits = s.GetBits(256, 1) // Out of range
	if bits != 0 {
		t.Error("GetBits should return 0 for out-of-range offset")
	}

	bits = s.GetBits(0, 0) // Zero count
	if bits != 0 {
		t.Error("GetBits should return 0 for zero count")
	}
}

func BenchmarkScalarAdd(b *testing.B) {
	a := One()
	x := One()
	result := Zero()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.Add(a, x)
	}
}

func BenchmarkScalarMul(b *testing.B) {
	a := One()
	x := One()
	result := Zero()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.Mul(a, x)
	}
}

func BenchmarkScalarSquare(b *testing.B) {
	a := One()
	result := Zero()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.Square(a)
	}
}

func BenchmarkScalarInverse(b *testing.B) {
	a := One()
	result := Zero()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.Inverse(a)
	}
}
