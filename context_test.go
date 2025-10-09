package secp256k1

import (
	"testing"

	"github.com/rafaelescrich/go-secp256k1/scalar"
)

func TestContextPrecomputedTables(t *testing.T) {
	ctx := NewContext()

	// Test that precomputed tables are valid
	if !ctx.ValidatePrecomputedTables() {
		t.Error("Precomputed tables validation failed")
	}

	// Test that we have the expected number of precomputed values
	if len(ctx.precomputedG) != 16 {
		t.Errorf("Expected 16 precomputed values, got %d", len(ctx.precomputedG))
	}
}

func TestContextFastScalarMult(t *testing.T) {
	ctx := NewContext()

	// Test vectors for scalar multiplication
	testCases := []struct {
		name   string
		scalar []byte
	}{
		{
			name:   "Small scalar",
			scalar: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5},
		},
		{
			name:   "Medium scalar",
			scalar: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3},
		},
		{
			name:   "Large scalar",
			scalar: []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create scalar from test case
			k := scalar.Zero()
			if !k.SetBytes(tc.scalar) {
				t.Fatalf("Failed to create scalar from bytes")
			}

			// Compute using fast scalar multiplication
			fastResult := ctx.FastScalarMult(k)

			// Compute using regular scalar multiplication for comparison
			privKey, err := PrivateKeyFromBytes(tc.scalar)
			if err != nil {
				t.Fatalf("Failed to create private key: %v", err)
			}
			pubKey := privKey.PublicKey()
			regularResult := pubKey.point

			// Compare results
			if !fastResult.Equal(regularResult) {
				t.Errorf("Fast scalar multiplication result doesn't match regular result")
				t.Errorf("Fast result: x=%x, y=%x", fastResult.X().Bytes(), fastResult.Y().Bytes())
				t.Errorf("Regular result: x=%x, y=%x", regularResult.X().Bytes(), regularResult.Y().Bytes())
			}
		})
	}
}

func TestContextModes(t *testing.T) {
	// Test strict mode
	strictCtx := NewContextWithMode(ModeStrict)
	if strictCtx.GetSignatureMode() != ModeStrict {
		t.Error("Expected strict mode")
	}

	// Test compatible mode
	compatCtx := NewContextWithMode(ModeCompatible)
	if compatCtx.GetSignatureMode() != ModeCompatible {
		t.Error("Expected compatible mode")
	}

	// Test signature verification toggle
	ctx := NewContext()
	ctx.SetVerifySignatures(false)
	if ctx.verifySignatures != false {
		t.Error("Expected signature verification to be disabled")
	}

	ctx.SetVerifySignatures(true)
	if ctx.verifySignatures != true {
		t.Error("Expected signature verification to be enabled")
	}
}

func TestContextECDSAWithContext(t *testing.T) {
	ctx := NewContext()

	// Generate test key and message
	privKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	pubKey := privKey.PublicKey()
	msgHash := make([]byte, 32)
	for i := range msgHash {
		msgHash[i] = byte(i)
	}

	// Sign using context
	sig, err := ctx.SignECDSA(privKey, msgHash)
	if err != nil {
		t.Fatalf("Failed to sign with context: %v", err)
	}

	// Verify using context
	if !ctx.VerifyECDSA(pubKey, sig, msgHash) {
		t.Error("Context ECDSA verification failed")
	}

	// Test with verification disabled
	ctx.SetVerifySignatures(false)
	if !ctx.VerifyECDSA(pubKey, sig, msgHash) {
		t.Error("Context should skip verification when disabled")
	}

	// Test with wrong signature (should still pass when verification is disabled)
	wrongSig := &Signature{r: sig.s, s: sig.r} // Swap r and s
	if !ctx.VerifyECDSA(pubKey, wrongSig, msgHash) {
		t.Error("Context should skip verification when disabled, even for wrong signatures")
	}

	// Re-enable verification and test wrong signature
	ctx.SetVerifySignatures(true)
	if ctx.VerifyECDSA(pubKey, wrongSig, msgHash) {
		t.Error("Context should reject wrong signature when verification is enabled")
	}
}

func BenchmarkContextFastScalarMult(b *testing.B) {
	ctx := NewContext()

	// Create a test scalar
	k := scalar.Zero()
	testBytes := []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}
	k.SetBytes(testBytes)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.FastScalarMult(k)
	}
}

func BenchmarkRegularScalarMult(b *testing.B) {
	// Create a test scalar and private key
	testBytes := []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}
	privKey, _ := PrivateKeyFromBytes(testBytes)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		privKey.PublicKey()
	}
}
