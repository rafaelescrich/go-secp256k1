package schnorr

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/rafaelescrich/go-secp256k1/group"
	"github.com/rafaelescrich/go-secp256k1/scalar"
)

func TestSchnorrSignAndVerify(t *testing.T) {
	// Create a test private key
	privkey := scalar.One()

	// Derive public key
	g := group.Generator()
	pubkey := group.Infinity().ScalarMult(privkey, g)

	// Create test message
	msg := sha256.Sum256([]byte("Hello, BIP-340!"))

	// Sign the message
	sig, err := Sign(privkey, msg[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify the signature
	valid := Verify(pubkey, msg[:], sig)
	if !valid {
		t.Error("Signature verification failed")
	}

	// Test with wrong message
	wrongMsg := sha256.Sum256([]byte("Wrong message"))
	valid = Verify(pubkey, wrongMsg[:], sig)
	if valid {
		t.Error("Signature should not verify with wrong message")
	}
}

func TestSchnorrSignatureEncoding(t *testing.T) {
	// Create a test signature
	privkey := scalar.One()
	msg := sha256.Sum256([]byte("Test message"))

	sig, err := Sign(privkey, msg[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Test encoding
	sigBytes := sig.Bytes()
	if len(sigBytes) != 64 {
		t.Errorf("Signature should be 64 bytes, got %d", len(sigBytes))
	}

	// Test decoding
	sig2, err := SignatureFromBytes(sigBytes)
	if err != nil {
		t.Errorf("Failed to decode signature: %v", err)
	}

	// Verify that decoded signature works
	g := group.Generator()
	pubkey := group.Infinity().ScalarMult(privkey, g)

	valid := Verify(pubkey, msg[:], sig2)
	if !valid {
		t.Error("Decoded signature verification failed")
	}

	// Test that original and decoded signatures are equal
	if !bytes.Equal(sig.Bytes(), sig2.Bytes()) {
		t.Error("Original and decoded signatures should be equal")
	}
}

func TestSchnorrInvalidInputs(t *testing.T) {
	privkey := scalar.One()
	g := group.Generator()
	pubkey := group.Infinity().ScalarMult(privkey, g)

	// Test with invalid message length
	shortMsg := []byte("short")
	_, err := Sign(privkey, shortMsg)
	if err == nil {
		t.Error("Sign should fail with invalid message length")
	}

	valid := Verify(pubkey, shortMsg, &Signature{})
	if valid {
		t.Error("Verify should fail with invalid message length")
	}

	// Test with invalid signature encoding
	invalidSig := make([]byte, 63) // Wrong length
	_, err = SignatureFromBytes(invalidSig)
	if err == nil {
		t.Error("SignatureFromBytes should fail with invalid length")
	}

	// Test with point at infinity as public key
	infinity := group.Infinity()
	validMsg := make([]byte, 32)
	valid = Verify(infinity, validMsg, &Signature{})
	if valid {
		t.Error("Verify should fail with point at infinity as public key")
	}
}

func TestSchnorrDeterministic(t *testing.T) {
	// Test that signing is deterministic
	privkey := scalar.One()
	msg := sha256.Sum256([]byte("Deterministic test"))

	sig1, err := Sign(privkey, msg[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	sig2, err := Sign(privkey, msg[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	if !bytes.Equal(sig1.Bytes(), sig2.Bytes()) {
		t.Error("Schnorr signatures should be deterministic")
	}
}

func TestSchnorrBIP340TestVectors(t *testing.T) {
	// This would contain official BIP-340 test vectors
	// For now, we'll test with a simple known case

	// Test vector: private key = 1, message = hash("test")
	privkey := scalar.One()
	msg := sha256.Sum256([]byte("test"))

	sig, err := Sign(privkey, msg[:])
	if err != nil {
		t.Fatalf("Failed to sign test vector: %v", err)
	}

	// Derive public key
	g := group.Generator()
	pubkey := group.Infinity().ScalarMult(privkey, g)

	// Verify
	valid := Verify(pubkey, msg[:], sig)
	if !valid {
		t.Error("Test vector verification failed")
	}
}

func BenchmarkSchnorrSign(b *testing.B) {
	privkey := scalar.One()
	msg := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Sign(privkey, msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSchnorrVerify(b *testing.B) {
	privkey := scalar.One()
	msg := make([]byte, 32)
	sig, _ := Sign(privkey, msg)

	g := group.Generator()
	pubkey := group.Infinity().ScalarMult(privkey, g)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid := Verify(pubkey, msg, sig)
		if !valid {
			b.Fatal("Verification failed")
		}
	}
}
