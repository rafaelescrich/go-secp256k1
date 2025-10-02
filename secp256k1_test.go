package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestKeyGeneration(t *testing.T) {
	// Test private key generation
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	if priv == nil {
		t.Fatal("Generated private key is nil")
	}

	// Test that private key bytes are 32 bytes
	privBytes := priv.Bytes()
	if len(privBytes) != 32 {
		t.Errorf("Private key should be 32 bytes, got %d", len(privBytes))
	}

	// Test public key derivation
	pub := priv.PublicKey()
	if pub == nil {
		t.Fatal("Derived public key is nil")
	}

	// Test that public key bytes are 33 bytes (compressed)
	pubBytes := pub.Bytes()
	if len(pubBytes) != 33 {
		t.Errorf("Public key should be 33 bytes, got %d", len(pubBytes))
	}

	// Test that x-only public key is 32 bytes
	xOnlyBytes := pub.XOnlyBytes()
	if len(xOnlyBytes) != 32 {
		t.Errorf("X-only public key should be 32 bytes, got %d", len(xOnlyBytes))
	}
}

func TestPrivateKeyFromBytes(t *testing.T) {
	// Test valid private key
	validKey := make([]byte, 32)
	validKey[31] = 1 // Set to 1
	
	priv, err := PrivateKeyFromBytes(validKey)
	if err != nil {
		t.Errorf("Failed to create private key from valid bytes: %v", err)
	}

	// Test that bytes round-trip correctly
	resultBytes := priv.Bytes()
	if !bytes.Equal(validKey, resultBytes) {
		t.Error("Private key bytes should round-trip correctly")
	}

	// Test invalid length
	invalidKey := make([]byte, 31)
	_, err = PrivateKeyFromBytes(invalidKey)
	if err == nil {
		t.Error("Should fail for invalid key length")
	}

	// Test zero key
	zeroKey := make([]byte, 32)
	_, err = PrivateKeyFromBytes(zeroKey)
	if err == nil {
		t.Error("Should fail for zero private key")
	}
}

func TestPublicKeyFromBytes(t *testing.T) {
	// Generate a valid key pair first
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	pub := priv.PublicKey()
	pubBytes := pub.Bytes()

	// Test round-trip
	pub2, err := PublicKeyFromBytes(pubBytes)
	if err != nil {
		t.Errorf("Failed to create public key from bytes: %v", err)
	}

	pub2Bytes := pub2.Bytes()
	if !bytes.Equal(pubBytes, pub2Bytes) {
		t.Error("Public key bytes should round-trip correctly")
	}

	// Test invalid length
	invalidPub := make([]byte, 32)
	_, err = PublicKeyFromBytes(invalidPub)
	if err == nil {
		t.Error("Should fail for invalid public key length")
	}
}

func TestECDSASignAndVerify(t *testing.T) {
	// Generate key pair
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	pub := priv.PublicKey()

	// Create a test message hash
	msg := []byte("Hello, secp256k1!")
	msgHash := sha256.Sum256(msg)

	// Sign the message
	sig, err := priv.SignECDSA(msgHash[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	if sig == nil {
		t.Fatal("Signature is nil")
	}

	// Verify the signature
	valid := pub.VerifyECDSA(sig, msgHash[:])
	if !valid {
		t.Error("Signature verification failed")
	}

	// Test with wrong message
	wrongMsg := []byte("Wrong message")
	wrongHash := sha256.Sum256(wrongMsg)
	valid = pub.VerifyECDSA(sig, wrongHash[:])
	if valid {
		t.Error("Signature should not verify with wrong message")
	}

	// Test signature serialization
	sigBytes := sig.Bytes()
	if len(sigBytes) != 64 {
		t.Errorf("Signature should be 64 bytes, got %d", len(sigBytes))
	}

	// Test signature deserialization
	sig2, err := SignatureFromBytes(sigBytes)
	if err != nil {
		t.Errorf("Failed to deserialize signature: %v", err)
	}

	valid = pub.VerifyECDSA(sig2, msgHash[:])
	if !valid {
		t.Error("Deserialized signature verification failed")
	}
}

func TestSchnorrSignAndVerify(t *testing.T) {
	// Generate key pair
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	pub := priv.PublicKey()

	// Create a test message (32 bytes for Schnorr)
	msg := sha256.Sum256([]byte("Hello, Schnorr!"))

	// Sign the message
	sig, err := priv.SignSchnorr(msg[:])
	if err != nil {
		t.Fatalf("Failed to sign message with Schnorr: %v", err)
	}

	if sig == nil {
		t.Fatal("Schnorr signature is nil")
	}

	// Verify the signature
	valid := pub.VerifySchnorr(sig, msg[:])
	if !valid {
		t.Error("Schnorr signature verification failed")
	}

	// Test with wrong message
	wrongMsg := sha256.Sum256([]byte("Wrong message"))
	valid = pub.VerifySchnorr(sig, wrongMsg[:])
	if valid {
		t.Error("Schnorr signature should not verify with wrong message")
	}

	// Test signature serialization
	sigBytes := sig.Bytes()
	if len(sigBytes) != 64 {
		t.Errorf("Schnorr signature should be 64 bytes, got %d", len(sigBytes))
	}

	// Test signature deserialization
	sig2, err := SchnorrSignatureFromBytes(sigBytes)
	if err != nil {
		t.Errorf("Failed to deserialize Schnorr signature: %v", err)
	}

	valid = pub.VerifySchnorr(sig2, msg[:])
	if !valid {
		t.Error("Deserialized Schnorr signature verification failed")
	}
}

func TestInvalidInputs(t *testing.T) {
	priv, _ := GeneratePrivateKey()
	pub := priv.PublicKey()

	// Test ECDSA with invalid message length
	shortMsg := []byte("short")
	_, err := priv.SignECDSA(shortMsg)
	if err == nil {
		t.Error("ECDSA signing should fail with invalid message length")
	}

	// Test Schnorr with invalid message length
	_, err = priv.SignSchnorr(shortMsg)
	if err == nil {
		t.Error("Schnorr signing should fail with invalid message length")
	}

	// Test verification with invalid message length
	validMsg := make([]byte, 32)
	sig, _ := priv.SignECDSA(validMsg)
	
	valid := pub.VerifyECDSA(sig, shortMsg)
	if valid {
		t.Error("ECDSA verification should fail with invalid message length")
	}

	schnorrSig, _ := priv.SignSchnorr(validMsg)
	valid = pub.VerifySchnorr(schnorrSig, shortMsg)
	if valid {
		t.Error("Schnorr verification should fail with invalid message length")
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GeneratePrivateKey()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPublicKeyDerivation(b *testing.B) {
	priv, _ := GeneratePrivateKey()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = priv.PublicKey()
	}
}

func BenchmarkECDSASign(b *testing.B) {
	priv, _ := GeneratePrivateKey()
	msg := make([]byte, 32)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := priv.SignECDSA(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkECDSAVerify(b *testing.B) {
	priv, _ := GeneratePrivateKey()
	pub := priv.PublicKey()
	msg := make([]byte, 32)
	sig, _ := priv.SignECDSA(msg)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid := pub.VerifyECDSA(sig, msg)
		if !valid {
			b.Fatal("Verification failed")
		}
	}
}

func BenchmarkSchnorrSign(b *testing.B) {
	priv, _ := GeneratePrivateKey()
	msg := make([]byte, 32)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := priv.SignSchnorr(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSchnorrVerify(b *testing.B) {
	priv, _ := GeneratePrivateKey()
	pub := priv.PublicKey()
	msg := make([]byte, 32)
	sig, _ := priv.SignSchnorr(msg)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid := pub.VerifySchnorr(sig, msg)
		if !valid {
			b.Fatal("Verification failed")
		}
	}
}
