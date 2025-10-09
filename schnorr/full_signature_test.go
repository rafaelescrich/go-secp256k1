package schnorr

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/rafaelescrich/go-secp256k1/group"
	"github.com/rafaelescrich/go-secp256k1/scalar"
)

func TestFullSignatureSignAndVerify(t *testing.T) {
	// Create a test private key
	privkey := scalar.One()

	// Derive public key
	g := group.Generator()
	pubkey := group.Infinity().ScalarMult(privkey, g)

	// Create test message
	msg := sha256.Sum256([]byte("Full signature test"))

	// Sign the message
	sig, err := SignFull(privkey, msg[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify the signature
	valid := VerifyFull(pubkey, msg[:], sig)
	if !valid {
		t.Error("Full signature verification failed")
	}

	// Test with wrong message
	wrongMsg := sha256.Sum256([]byte("Wrong message"))
	valid = VerifyFull(pubkey, wrongMsg[:], sig)
	if valid {
		t.Error("Full signature should not verify with wrong message")
	}
}

func TestFullSignatureEncoding(t *testing.T) {
	// Create a test signature
	privkey := scalar.One()
	msg := sha256.Sum256([]byte("Full signature encoding test"))

	sig, err := SignFull(privkey, msg[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Test encoding
	sigBytes := sig.Bytes()
	if len(sigBytes) != 96 {
		t.Errorf("Full signature should be 96 bytes, got %d", len(sigBytes))
	}

	// Test decoding
	sig2, err := FullSignatureFromBytes(sigBytes)
	if err != nil {
		t.Errorf("Failed to decode full signature: %v", err)
	}

	// Verify that decoded signature works
	g := group.Generator()
	pubkey := group.Infinity().ScalarMult(privkey, g)

	valid := VerifyFull(pubkey, msg[:], sig2)
	if !valid {
		t.Error("Decoded full signature verification failed")
	}

	// Test that original and decoded signatures are equal
	if !bytes.Equal(sig.Bytes(), sig2.Bytes()) {
		t.Error("Original and decoded full signatures should be equal")
	}
}

func TestFullSignatureComponents(t *testing.T) {
	// Create a test signature
	privkey := scalar.One()
	msg := sha256.Sum256([]byte("Component test"))

	sig, err := SignFull(privkey, msg[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Test component accessors
	rx := sig.RX()
	ry := sig.RY()
	s := sig.S()

	if rx == nil || ry == nil || s == nil {
		t.Error("Signature components should not be nil")
	}

	// Verify components are valid
	if !isValidFieldElement(rx) {
		t.Error("RX component should be valid")
	}

	if !isValidFieldElement(ry) {
		t.Error("RY component should be valid")
	}

	if !isValidScalar(s) {
		t.Error("S component should be valid")
	}
}

func TestFullSignatureInvalidInputs(t *testing.T) {
	privkey := scalar.One()
	g := group.Generator()
	pubkey := group.Infinity().ScalarMult(privkey, g)

	// Test with invalid message length
	shortMsg := []byte("short")
	_, err := SignFull(privkey, shortMsg)
	if err == nil {
		t.Error("SignFull should fail with invalid message length")
	}

	valid := VerifyFull(pubkey, shortMsg, &FullSignature{})
	if valid {
		t.Error("VerifyFull should fail with invalid message length")
	}

	// Test with invalid signature encoding
	invalidSig := make([]byte, 95) // Wrong length
	_, err = FullSignatureFromBytes(invalidSig)
	if err == nil {
		t.Error("FullSignatureFromBytes should fail with invalid length")
	}

	// Test with point at infinity as public key
	infinity := group.Infinity()
	validMsg := make([]byte, 32)
	valid = VerifyFull(infinity, validMsg, &FullSignature{})
	if valid {
		t.Error("VerifyFull should fail with point at infinity as public key")
	}
}

func TestFullSignatureDeterministic(t *testing.T) {
	// Test that full signing is deterministic
	privkey := scalar.One()
	msg := sha256.Sum256([]byte("Deterministic full signature test"))

	sig1, err := SignFull(privkey, msg[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	sig2, err := SignFull(privkey, msg[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	if !bytes.Equal(sig1.Bytes(), sig2.Bytes()) {
		t.Error("Full signatures should be deterministic")
	}
}

func TestFullSignatureVsStandard(t *testing.T) {
	// Compare full signature with standard signature behavior
	privkey := scalar.One()
	msg := sha256.Sum256([]byte("Comparison test"))

	// Create both signature types
	standardSig, err := Sign(privkey, msg[:])
	if err != nil {
		t.Fatalf("Failed to create standard signature: %v", err)
	}

	fullSig, err := SignFull(privkey, msg[:])
	if err != nil {
		t.Fatalf("Failed to create full signature: %v", err)
	}

	// Derive public key
	g := group.Generator()
	pubkey := group.Infinity().ScalarMult(privkey, g)

	// Both should verify successfully
	standardValid := Verify(pubkey, msg[:], standardSig)
	if !standardValid {
		t.Error("Standard signature should verify")
	}

	fullValid := VerifyFull(pubkey, msg[:], fullSig)
	if !fullValid {
		t.Error("Full signature should verify")
	}

	// The R.x coordinates should match (assuming same nonce generation)
	if !standardSig.R().Equal(fullSig.RX()) {
		t.Error("Standard and full signatures should have same R.x coordinate")
	}
}

func TestFullSignatureWithDifferentKeys(t *testing.T) {
	// Test with various private keys
	// Create test keys
	key2 := scalar.Zero()
	key2Bytes := make([]byte, 32)
	key2Bytes[31] = 2
	key2.SetBytes(key2Bytes)

	key3 := scalar.Zero()
	key3Bytes := make([]byte, 32)
	key3Bytes[28] = 0xDE
	key3Bytes[29] = 0xAD
	key3Bytes[30] = 0xBE
	key3Bytes[31] = 0xEF
	key3.SetBytes(key3Bytes)

	testKeys := []*scalar.Scalar{
		scalar.One(),
		key2,
		key3,
	}

	msg := sha256.Sum256([]byte("Multi-key test"))
	g := group.Generator()

	for i, privkey := range testKeys {
		t.Run(fmt.Sprintf("Key_%d", i), func(t *testing.T) {
			// Create signature
			sig, err := SignFull(privkey, msg[:])
			if err != nil {
				t.Fatalf("Failed to sign with key %d: %v", i, err)
			}

			// Derive public key and verify
			pubkey := group.Infinity().ScalarMult(privkey, g)
			valid := VerifyFull(pubkey, msg[:], sig)
			if !valid {
				t.Errorf("Signature verification failed for key %d", i)
			}

			// Test signature encoding/decoding
			sigBytes := sig.Bytes()
			decodedSig, err := FullSignatureFromBytes(sigBytes)
			if err != nil {
				t.Errorf("Failed to decode signature for key %d: %v", i, err)
			}

			decodedValid := VerifyFull(pubkey, msg[:], decodedSig)
			if !decodedValid {
				t.Errorf("Decoded signature verification failed for key %d", i)
			}
		})
	}
}

func BenchmarkSignFull(b *testing.B) {
	privkey := scalar.One()
	msg := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := SignFull(privkey, msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyFull(b *testing.B) {
	privkey := scalar.One()
	msg := make([]byte, 32)
	sig, _ := SignFull(privkey, msg)

	g := group.Generator()
	pubkey := group.Infinity().ScalarMult(privkey, g)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid := VerifyFull(pubkey, msg, sig)
		if !valid {
			b.Fatal("Verification failed")
		}
	}
}

func BenchmarkFullSignatureEncoding(b *testing.B) {
	privkey := scalar.One()
	msg := make([]byte, 32)
	sig, _ := SignFull(privkey, msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sigBytes := sig.Bytes()
		_, err := FullSignatureFromBytes(sigBytes)
		if err != nil {
			b.Fatal(err)
		}
	}
}
