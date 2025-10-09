package group

import (
	"testing"

	"github.com/rafaelescrich/go-secp256k1/scalar"
)

// Test optimized point operations against regular operations
func TestOptimizedPointOperations(t *testing.T) {
	// Test point addition
	g := Generator()
	p1 := Infinity().ScalarMult(scalar.One(), g)
	p2 := Infinity().ScalarMult(scalar.One().Add(scalar.One(), scalar.One()), g) // 2*G

	// Regular addition
	resultRegular := Infinity()
	resultRegular.Add(p1, p2)

	// Optimized addition
	resultOptimized := Infinity()
	resultOptimized.AddOptimized(p1, p2)

	// Compare results
	if !resultRegular.X().Equal(resultOptimized.X()) || !resultRegular.Y().Equal(resultOptimized.Y()) {
		t.Error("Optimized point addition produces different result than regular addition")
	}

	// Test point doubling
	resultRegular.Double(p1)
	resultOptimized.DoubleOptimized(p1)

	if !resultRegular.X().Equal(resultOptimized.X()) || !resultRegular.Y().Equal(resultOptimized.Y()) {
		t.Error("Optimized point doubling produces different result than regular doubling")
	}
}

func TestOptimizedScalarMultiplication(t *testing.T) {
	g := Generator()
	k := scalar.One()
	k.Add(k, scalar.One()) // k = 2

	// Regular scalar multiplication
	resultRegular := Infinity()
	resultRegular.ScalarMult(k, g)

	// Optimized scalar multiplication
	resultOptimized := Infinity()
	resultOptimized.ScalarMultOptimized(k, g)

	// Compare results
	if !resultRegular.X().Equal(resultOptimized.X()) || !resultRegular.Y().Equal(resultOptimized.Y()) {
		t.Error("Optimized scalar multiplication produces different result than regular multiplication")
	}
}

// Benchmark point operations
func BenchmarkPointAddRegular(b *testing.B) {
	g := Generator()
	p1 := Infinity().ScalarMult(scalar.One(), g)
	p2 := Infinity().ScalarMult(scalar.One().Add(scalar.One(), scalar.One()), g)
	result := Infinity()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.Add(p1, p2)
	}
}

func BenchmarkPointAddOptimized(b *testing.B) {
	g := Generator()
	p1 := Infinity().ScalarMult(scalar.One(), g)
	p2 := Infinity().ScalarMult(scalar.One().Add(scalar.One(), scalar.One()), g)
	result := Infinity()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.AddOptimized(p1, p2)
	}
}

func BenchmarkPointDoubleRegular(b *testing.B) {
	g := Generator()
	p := Infinity().ScalarMult(scalar.One(), g)
	result := Infinity()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.Double(p)
	}
}

func BenchmarkPointDoubleOptimized(b *testing.B) {
	g := Generator()
	p := Infinity().ScalarMult(scalar.One(), g)
	result := Infinity()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.DoubleOptimized(p)
	}
}

func BenchmarkScalarMultRegular(b *testing.B) {
	g := Generator()
	k := scalar.One()
	// Create a non-trivial scalar
	kBytes := []byte{
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
	}
	k.SetBytes(kBytes)
	result := Infinity()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.ScalarMult(k, g)
	}
}

func BenchmarkScalarMultOptimized(b *testing.B) {
	g := Generator()
	k := scalar.One()
	// Create a non-trivial scalar
	kBytes := []byte{
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
	}
	k.SetBytes(kBytes)
	result := Infinity()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.ScalarMultOptimized(k, g)
	}
}
