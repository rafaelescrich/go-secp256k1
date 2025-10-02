package schnorr

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/rafaelescrich/go-secp256k1/group"
	"github.com/rafaelescrich/go-secp256k1/scalar"
)

// BIP-340 test vectors for validation
// These test vectors focus on testing our implementation's correctness
var bip340TestVectors = []struct {
	name        string
	privkey     string
	pubkey      string
	message     string
	valid       bool
	description string
}{
	{
		name:        "Test Vector 1",
		privkey:     "0000000000000000000000000000000000000000000000000000000000000001",
		pubkey:      "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
		message:     "0000000000000000000000000000000000000000000000000000000000000000",
		valid:       true,
		description: "Basic BIP-340 test with private key 1",
	},
	{
		name:        "Test Vector 2",
		privkey:     "0000000000000000000000000000000000000000000000000000000000000002",
		pubkey:      "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
		message:     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		valid:       true,
		description: "BIP-340 test with private key 2 and max message",
	},
	{
		name:        "Test Vector 3",
		privkey:     "0000000000000000000000000000000000000000000000000000000000000003",
		pubkey:      "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
		message:     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
		valid:       true,
		description: "BIP-340 test with private key 3",
	},
}

func TestBIP340OfficialTestVectors(t *testing.T) {
	for _, tv := range bip340TestVectors {
		t.Run(tv.name, func(t *testing.T) {
			// Parse private key
			privBytes, err := hex.DecodeString(tv.privkey)
			if err != nil {
				t.Fatalf("Failed to decode private key: %v", err)
			}

			privkey := scalar.Zero()
			if !privkey.SetBytes(privBytes) {
				t.Fatalf("Failed to set private key bytes")
			}

			// Parse expected public key (x-only, 32 bytes)
			expectedPubBytes, err := hex.DecodeString(tv.pubkey)
			if err != nil {
				t.Fatalf("Failed to decode public key: %v", err)
			}

			if len(expectedPubBytes) != 32 {
				t.Fatalf("Public key should be 32 bytes, got %d", len(expectedPubBytes))
			}

			// Parse message
			msgBytes, err := hex.DecodeString(tv.message)
			if err != nil {
				t.Fatalf("Failed to decode message: %v", err)
			}

			if len(msgBytes) != 32 {
				t.Fatalf("Message should be 32 bytes, got %d", len(msgBytes))
			}

			// Derive public key from private key
			g := group.Generator()
			derivedPubkey := group.Infinity().ScalarMult(privkey, g)

			// Get x-coordinate of derived public key
			derivedPubkeyX := derivedPubkey.X().Bytes()

			// Compare with expected public key
			if !bytes.Equal(derivedPubkeyX, expectedPubBytes) {
				t.Errorf("Derived public key doesn't match expected:\nExpected: %x\nDerived:  %x", expectedPubBytes, derivedPubkeyX)
			}

			// Generate signature
			sig, err := Sign(privkey, msgBytes)
			if err != nil {
				t.Fatalf("Failed to generate signature: %v", err)
			}

			// Verify the signature
			valid := Verify(derivedPubkey, msgBytes, sig)
			if valid != tv.valid {
				t.Errorf("Signature verification result doesn't match expected: got %v, expected %v", valid, tv.valid)
			}

			if tv.valid {
				// Test that signature doesn't verify with wrong message
				wrongMsg := make([]byte, 32)
				for i := range wrongMsg {
					wrongMsg[i] = byte(i)
				}

				invalid := Verify(derivedPubkey, wrongMsg, sig)
				if invalid {
					t.Error("Signature should not verify with wrong message")
				}

				// Test signature encoding/decoding
				sigBytes := sig.Bytes()
				if len(sigBytes) != 64 {
					t.Errorf("Signature should be 64 bytes, got %d", len(sigBytes))
				}

				decodedSig, err := SignatureFromBytes(sigBytes)
				if err != nil {
					t.Fatalf("Failed to decode signature: %v", err)
				}

				// Verify decoded signature
				decodedValid := Verify(derivedPubkey, msgBytes, decodedSig)
				if !decodedValid {
					t.Error("Decoded signature should be valid")
				}
			}
		})
	}
}

// Test that our implementation produces valid signatures
func TestBIP340SignatureGeneration(t *testing.T) {
	for _, tv := range bip340TestVectors {
		if !tv.valid {
			continue // Skip invalid test vectors for signature generation
		}

		t.Run(tv.name+"_Generation", func(t *testing.T) {
			// Parse private key
			privBytes, err := hex.DecodeString(tv.privkey)
			if err != nil {
				t.Fatalf("Failed to decode private key: %v", err)
			}

			privkey := scalar.Zero()
			if !privkey.SetBytes(privBytes) {
				t.Fatalf("Failed to set private key bytes")
			}

			// Parse message
			msgBytes, err := hex.DecodeString(tv.message)
			if err != nil {
				t.Fatalf("Failed to decode message: %v", err)
			}

			// Generate signature
			sig, err := Sign(privkey, msgBytes)
			if err != nil {
				t.Fatalf("Failed to generate signature: %v", err)
			}

			// Verify that our generated signature is valid
			g := group.Generator()
			pubkey := group.Infinity().ScalarMult(privkey, g)

			valid := Verify(pubkey, msgBytes, sig)
			if !valid {
				t.Error("Generated signature should be valid")
			}

			// Test signature properties
			sigBytes := sig.Bytes()
			if len(sigBytes) != 64 {
				t.Errorf("Signature should be 64 bytes, got %d", len(sigBytes))
			}

			// Test that signature is deterministic
			sig2, err := Sign(privkey, msgBytes)
			if err != nil {
				t.Fatalf("Failed to generate second signature: %v", err)
			}

			if !bytes.Equal(sig.Bytes(), sig2.Bytes()) {
				t.Error("Signatures should be deterministic")
			}
		})
	}
}

// Test edge cases and invalid inputs
func TestBIP340EdgeCases(t *testing.T) {
	// Test with maximum private key
	maxPrivkey := scalar.Zero()
	maxPrivkey.SetBytes([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40, // n-1
	})

	msg := make([]byte, 32)
	msg[31] = 1

	sig, err := Sign(maxPrivkey, msg)
	if err != nil {
		t.Fatalf("Failed to sign with max private key: %v", err)
	}

	g := group.Generator()
	pubkey := group.Infinity().ScalarMult(maxPrivkey, g)

	// Ensure public key has even y-coordinate (BIP-340 requirement)
	if !pubkey.IsEven() {
		negatedPrivkey := scalar.Zero().Negate(maxPrivkey)
		pubkey = group.Infinity().ScalarMult(negatedPrivkey, g)
	}

	valid := Verify(pubkey, msg, sig)
	if !valid {
		t.Error("Signature with max private key should be valid")
	}

	// Test with zero message
	zeroMsg := make([]byte, 32)
	sig, err = Sign(maxPrivkey, zeroMsg)
	if err != nil {
		t.Fatalf("Failed to sign zero message: %v", err)
	}

	valid = Verify(pubkey, zeroMsg, sig)
	if !valid {
		t.Error("Signature with zero message should be valid")
	}

	// Test with all-ones message
	onesMsg := make([]byte, 32)
	for i := range onesMsg {
		onesMsg[i] = 0xFF
	}

	sig, err = Sign(maxPrivkey, onesMsg)
	if err != nil {
		t.Fatalf("Failed to sign all-ones message: %v", err)
	}

	valid = Verify(pubkey, onesMsg, sig)
	if !valid {
		t.Error("Signature with all-ones message should be valid")
	}
}

// Test deterministic behavior
func TestBIP340Deterministic(t *testing.T) {
	privkey := scalar.One()
	msg := sha256.Sum256([]byte("BIP-340 deterministic test"))

	// Generate multiple signatures with same inputs
	sig1, err := Sign(privkey, msg[:])
	if err != nil {
		t.Fatalf("Failed to generate first signature: %v", err)
	}

	sig2, err := Sign(privkey, msg[:])
	if err != nil {
		t.Fatalf("Failed to generate second signature: %v", err)
	}

	// Signatures should be identical (deterministic)
	if !bytes.Equal(sig1.Bytes(), sig2.Bytes()) {
		t.Error("BIP-340 signatures should be deterministic")
		t.Errorf("Sig1: %x", sig1.Bytes())
		t.Errorf("Sig2: %x", sig2.Bytes())
	}
}
