package scalar

import (
	"bytes"
	"testing"
)

// Test optimized uint64 scalar operations against the original methods
func TestScalarOptimizedOperations(t *testing.T) {
	// Test with known values
	aBytes := []byte{
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
	}

	bBytes := []byte{
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	}

	// Create scalar elements
	a := Zero()
	b := Zero()
	a.SetBytes(aBytes)
	b.SetBytes(bBytes)

	// Test optimized addition vs regular addition
	resultOptimized := Zero()
	resultOptimized.AddUint64(a, b)

	resultRegular := Zero()
	resultRegular.Add(a, b)

	if !bytes.Equal(resultOptimized.Bytes(), resultRegular.Bytes()) {
		t.Errorf("Optimized addition mismatch:\nOptimized: %x\nRegular:   %x",
			resultOptimized.Bytes(), resultRegular.Bytes())
	}

	// Test optimized multiplication vs regular multiplication
	resultOptimized.MulUint64(a, b)
	resultRegular.Mul(a, b)

	if !bytes.Equal(resultOptimized.Bytes(), resultRegular.Bytes()) {
		t.Errorf("Optimized multiplication mismatch:\nOptimized: %x\nRegular:   %x",
			resultOptimized.Bytes(), resultRegular.Bytes())
	}
}

// Benchmark optimized vs regular operations
func BenchmarkScalarAddRegular(b *testing.B) {
	a := One()
	x := One()
	result := Zero()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.Add(a, x)
	}
}

func BenchmarkScalarAddOptimized(b *testing.B) {
	a := One()
	x := One()
	result := Zero()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.AddUint64(a, x)
	}
}

func BenchmarkScalarMulRegular(b *testing.B) {
	a := One()
	x := One()
	// Set to non-trivial values
	aBytes := []byte{
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
	}
	a.SetBytes(aBytes)
	x.SetBytes(aBytes)

	result := Zero()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.Mul(a, x)
	}
}

func BenchmarkScalarMulOptimized(b *testing.B) {
	a := One()
	x := One()
	// Set to non-trivial values
	aBytes := []byte{
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
	}
	a.SetBytes(aBytes)
	x.SetBytes(aBytes)

	result := Zero()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.MulUint64(a, x)
	}
}
