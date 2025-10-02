package ecdh

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/rafaelescrich/go-secp256k1/group"
	"github.com/rafaelescrich/go-secp256k1/scalar"
)

// Known test vectors for secp256k1 ECDH
var ecdhTestVectors = []struct {
	name         string
	alicePrivate string
	alicePublic  string
	bobPrivate   string
	bobPublic    string
	sharedSecret string
	description  string
}{
	{
		name:         "Test Vector 1",
		alicePrivate: "0000000000000000000000000000000000000000000000000000000000000001",
		alicePublic:  "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
		bobPrivate:   "0000000000000000000000000000000000000000000000000000000000000002",
		bobPublic:    "02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
		sharedSecret: "0135DA2F8ACF7B9E3090939432E47684EB888EA38C2173054D4EEDFFDF152CA5",
		description:  "Basic ECDH test with small private keys",
	},
	{
		name:         "Test Vector 2",
		alicePrivate: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140",
		alicePublic:  "0379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
		bobPrivate:   "0000000000000000000000000000000000000000000000000000000000000001",
		bobPublic:    "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
		sharedSecret: "132F39A98C31BAADDBA6525F5D43F2954472097FA15265F45130BFDB70E51DEF",
		description:  "ECDH test with large private key",
	},
}

func TestECDHComputeSharedSecret(t *testing.T) {
	for _, tv := range ecdhTestVectors {
		t.Run(tv.name, func(t *testing.T) {
			// Parse Alice's private key
			alicePrivBytes, err := hex.DecodeString(tv.alicePrivate)
			if err != nil {
				t.Fatalf("Failed to decode Alice's private key: %v", err)
			}

			alicePriv := scalar.Zero()
			if !alicePriv.SetBytes(alicePrivBytes) {
				t.Fatalf("Failed to set Alice's private key bytes")
			}

			// Parse Bob's public key
			bobPubBytes, err := hex.DecodeString(tv.bobPublic)
			if err != nil {
				t.Fatalf("Failed to decode Bob's public key: %v", err)
			}

			bobPub := group.Infinity()
			if !bobPub.SetBytes(bobPubBytes) {
				t.Fatalf("Failed to set Bob's public key bytes")
			}

			// Compute shared secret from Alice's perspective
			sharedSecret1, err := ComputeSharedSecret(alicePriv, bobPub)
			if err != nil {
				t.Fatalf("Failed to compute shared secret: %v", err)
			}

			// Parse Bob's private key
			bobPrivBytes, err := hex.DecodeString(tv.bobPrivate)
			if err != nil {
				t.Fatalf("Failed to decode Bob's private key: %v", err)
			}

			bobPriv := scalar.Zero()
			if !bobPriv.SetBytes(bobPrivBytes) {
				t.Fatalf("Failed to set Bob's private key bytes")
			}

			// Parse Alice's public key
			alicePubBytes, err := hex.DecodeString(tv.alicePublic)
			if err != nil {
				t.Fatalf("Failed to decode Alice's public key: %v", err)
			}

			alicePub := group.Infinity()
			if !alicePub.SetBytes(alicePubBytes) {
				t.Fatalf("Failed to set Alice's public key bytes")
			}

			// Compute shared secret from Bob's perspective
			sharedSecret2, err := ComputeSharedSecret(bobPriv, alicePub)
			if err != nil {
				t.Fatalf("Failed to compute shared secret: %v", err)
			}

			// Both parties should get the same shared secret
			if len(sharedSecret1) != len(sharedSecret2) {
				t.Errorf("Shared secrets have different lengths: %d vs %d", len(sharedSecret1), len(sharedSecret2))
			}

			for i := range sharedSecret1 {
				if sharedSecret1[i] != sharedSecret2[i] {
					t.Errorf("Shared secrets differ at byte %d: %02x vs %02x", i, sharedSecret1[i], sharedSecret2[i])
				}
			}

			t.Logf("Shared secret: %x", sharedSecret1)
		})
	}
}

func TestECDHGenerateSharedSecret(t *testing.T) {
	// Test the convenience function
	privkey := scalar.Zero()
	privkey.SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})

	pubkeyBytes := []byte{0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98}

	sharedSecret, err := GenerateSharedSecret(privkey, pubkeyBytes)
	if err != nil {
		t.Fatalf("Failed to generate shared secret: %v", err)
	}

	if len(sharedSecret) != 32 {
		t.Errorf("Shared secret should be 32 bytes, got %d", len(sharedSecret))
	}

	// Test invalid public key length
	_, err = GenerateSharedSecret(privkey, []byte("short"))
	if err == nil {
		t.Error("Should fail for invalid public key length")
	}
}

func TestECDHValidation(t *testing.T) {
	// Test valid private key
	validPriv := scalar.Zero()
	validPriv.SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})

	if !ValidatePrivateKey(validPriv) {
		t.Error("Valid private key should pass validation")
	}

	// Test zero private key
	zeroPriv := scalar.Zero()
	if ValidatePrivateKey(zeroPriv) {
		t.Error("Zero private key should fail validation")
	}

	// Test valid public key
	validPub := group.Infinity()
	validPub.SetBytes([]byte{0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98})

	if !ValidatePublicKey(validPub) {
		t.Error("Valid public key should pass validation")
	}

	// Test point at infinity
	infinity := group.Infinity()
	if ValidatePublicKey(infinity) {
		t.Error("Point at infinity should fail validation")
	}
}

func TestECDHSymmetry(t *testing.T) {
	// Test that ECDH is symmetric (Alice and Bob get the same result)
	alicePriv := scalar.Zero()
	alicePriv.SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})

	bobPriv := scalar.Zero()
	bobPriv.SetBytes([]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33})

	// Generate public keys
	g := group.Generator()
	alicePub := group.Infinity().ScalarMult(alicePriv, g)
	bobPub := group.Infinity().ScalarMult(bobPriv, g)

	// Compute shared secrets
	secret1, err := ComputeSharedSecret(alicePriv, bobPub)
	if err != nil {
		t.Fatalf("Failed to compute shared secret 1: %v", err)
	}

	secret2, err := ComputeSharedSecret(bobPriv, alicePub)
	if err != nil {
		t.Fatalf("Failed to compute shared secret 2: %v", err)
	}

	// Compare secrets
	if len(secret1) != len(secret2) {
		t.Errorf("Shared secrets have different lengths")
	}

	for i := range secret1 {
		if secret1[i] != secret2[i] {
			t.Errorf("Shared secrets differ at byte %d", i)
		}
	}
}

func TestAffineScalarMultiply(t *testing.T) {
	basePointBytes := []byte{0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98}

	p := group.Infinity()
	if !p.SetBytes(basePointBytes) {
		t.Fatalf("failed to parse generator")
	}

	affine, err := newAffinePoint(p)
	if err != nil {
		t.Fatalf("failed to convert generator: %v", err)
	}

	resTwo := scalarMultiply(affine, big.NewInt(2))
	if resTwo.infinity {
		t.Fatalf("2*G returned infinity")
	}

	repeated := affineAdd(affine, affine)
	if repeated.infinity {
		t.Fatalf("affineAdd(G, G) returned infinity")
	}

	if resTwo.x.Cmp(repeated.x) != 0 || resTwo.y.Cmp(repeated.y) != 0 {
		t.Fatalf("scalar multiplication mismatch: got (%x,%x), expected (%x,%x)", resTwo.x, resTwo.y, repeated.x, repeated.y)
	}
}

func TestVectorPublicKeyConsistency(t *testing.T) {
	g := group.Generator()
	genAffine, err := newAffinePoint(g)
	if err != nil {
		t.Fatalf("failed to convert generator: %v", err)
	}

	for _, tv := range ecdhTestVectors {
		privBytes, err := hex.DecodeString(tv.alicePrivate)
		if err != nil {
			t.Fatalf("decode alice priv: %v", err)
		}

		derived := scalarMultiply(genAffine, new(big.Int).SetBytes(privBytes))
		if derived.infinity {
			t.Fatalf("derived infinity for %s", tv.name)
		}

		expected := group.Infinity()
		pubBytes, err := hex.DecodeString(tv.alicePublic)
		if err != nil {
			t.Fatalf("decode alice pub: %v", err)
		}
		if !expected.SetBytes(pubBytes) {
			t.Fatalf("invalid expected alice pub for %s", tv.name)
		}

		expectedAffine, err := newAffinePoint(expected)
		if err != nil {
			t.Fatalf("expected point invalid: %v", err)
		}

		if derived.x.Cmp(expectedAffine.x) != 0 || derived.y.Cmp(expectedAffine.y) != 0 {
			dx := fmt.Sprintf("%064x", derived.x)
			dy := fmt.Sprintf("%064x", derived.y)
			ex := fmt.Sprintf("%064x", expectedAffine.x)
			ey := fmt.Sprintf("%064x", expectedAffine.y)
			t.Fatalf("public key mismatch for %s: derived (%s,%s) expected (%s,%s)", tv.name, dx, dy, ex, ey)
		}
	}
}
