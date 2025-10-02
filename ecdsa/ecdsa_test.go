package ecdsa

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/rafaelescrich/go-secp256k1/group"
	"github.com/rafaelescrich/go-secp256k1/scalar"
)

// Known test vectors for secp256k1 ECDSA
var testVectors = []struct {
	name        string
	privateKey  string
	publicKey   string
	message     string
	signature   string
	description string
}{
	{
		name:        "Test Vector 1",
		privateKey:  "0000000000000000000000000000000000000000000000000000000000000001",
		publicKey:   "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
		message:     "Hello, World!",
		signature:   "3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
		description: "Basic ECDSA signature test",
	},
	{
		name:        "Test Vector 2",
		privateKey:  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140",
		publicKey:   "0379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
		message:     "Test message for ECDSA",
		signature:   "30440220FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD03641400220483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
		description: "Edge case with large private key",
	},
}

func TestECDSASignAndVerify(t *testing.T) {
	for _, tv := range testVectors {
		t.Run(tv.name, func(t *testing.T) {
			// Parse private key
			privBytes, err := hex.DecodeString(tv.privateKey)
			if err != nil {
				t.Fatalf("Failed to decode private key: %v", err)
			}

			privkey := scalar.Zero()
			if !privkey.SetBytes(privBytes) {
				t.Fatalf("Failed to set private key bytes")
			}

			// Parse public key
			pubBytes, err := hex.DecodeString(tv.publicKey)
			if err != nil {
				t.Fatalf("Failed to decode public key: %v", err)
			}

			pubkey := group.Infinity()
			if !pubkey.SetBytes(pubBytes) {
				t.Fatalf("Failed to set public key bytes")
			}

			// Hash the message
			msgHash := sha256.Sum256([]byte(tv.message))

			// Sign the message
			sig, err := Sign(privkey, msgHash[:])
			if err != nil {
				t.Fatalf("Failed to sign message: %v", err)
			}

			// Verify the signature
			valid := Verify(pubkey, msgHash[:], sig)
			if !valid {
				t.Errorf("Signature verification failed for %s", tv.description)
			}

			// Test that signature doesn't verify with wrong message
			wrongHash := sha256.Sum256([]byte("wrong message"))
			invalid := Verify(pubkey, wrongHash[:], sig)
			if invalid {
				t.Errorf("Signature should not verify with wrong message")
			}
		})
	}
}

func TestECDSASignatureEncoding(t *testing.T) {
	// Generate a test signature
	privkey := scalar.Zero()
	privkey.SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})

	msgHash := sha256.Sum256([]byte("test message"))
	sig, err := Sign(privkey, msgHash[:])
	if err != nil {
		t.Fatalf("Failed to create signature: %v", err)
	}

	// Test encoding
	sigBytes := sig.Bytes()
	if len(sigBytes) != 64 {
		t.Errorf("Signature should be 64 bytes, got %d", len(sigBytes))
	}

	// Test decoding
	sig2, err := SignatureFromBytes(sigBytes)
	if err != nil {
		t.Fatalf("Failed to decode signature: %v", err)
	}

	// Test that components match
	if !sig.R().Equal(sig2.R()) || !sig.S().Equal(sig2.S()) {
		t.Error("Signature encoding/decoding failed")
	}
}

func TestECDSAInvalidInputs(t *testing.T) {
	privkey := scalar.Zero()
	privkey.SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})

	pubkey := group.Infinity()
	pubkey.SetBytes([]byte{0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98})

	msgHash := sha256.Sum256([]byte("test"))

	// Test invalid message length
	_, err := Sign(privkey, []byte("short"))
	if err == nil {
		t.Error("Should fail for invalid message length")
	}

	// Test zero private key
	zeroPriv := scalar.Zero()
	_, err = Sign(zeroPriv, msgHash[:])
	if err == nil {
		t.Error("Should fail for zero private key")
	}

	// Test invalid signature
	invalidSig := &Signature{
		r: scalar.Zero(),
		s: scalar.Zero(),
	}
	valid := Verify(pubkey, msgHash[:], invalidSig)
	if valid {
		t.Error("Should fail for invalid signature")
	}
}

func TestECDSADeterministic(t *testing.T) {
	// Test that the same inputs produce the same signature
	privkey := scalar.Zero()
	privkey.SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})

	msgHash := sha256.Sum256([]byte("deterministic test"))

	sig1, err := Sign(privkey, msgHash[:])
	if err != nil {
		t.Fatalf("Failed to create first signature: %v", err)
	}

	sig2, err := Sign(privkey, msgHash[:])
	if err != nil {
		t.Fatalf("Failed to create second signature: %v", err)
	}

	// Signatures should be identical (deterministic)
	if !sig1.R().Equal(sig2.R()) || !sig1.S().Equal(sig2.S()) {
		t.Error("Signatures should be deterministic")
	}
}
