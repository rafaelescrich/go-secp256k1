// Package secp256k1 provides a pure Go implementation of the secp256k1 elliptic curve
// with support for ECDSA and Schnorr signatures (BIP-340).
package secp256k1

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/rafaelescrich/go-secp256k1/field"
	"github.com/rafaelescrich/go-secp256k1/group"
	"github.com/rafaelescrich/go-secp256k1/scalar"
)

// Context holds precomputed tables and configuration for cryptographic operations.
type Context struct {
	// Precomputed tables for efficient scalar multiplication
	// In a full implementation, this would contain precomputed multiples of G
}

// PublicKey represents a secp256k1 public key.
type PublicKey struct {
	point *group.Point
}

// PrivateKey represents a secp256k1 private key.
type PrivateKey struct {
	key *scalar.Scalar
}

// Signature represents an ECDSA signature.
type Signature struct {
	r, s *scalar.Scalar
}

// SchnorrSignature represents a BIP-340 Schnorr signature.
type SchnorrSignature struct {
	r *field.FieldVal // x-coordinate of R point
	s *scalar.Scalar  // signature scalar
}

// Common errors - generic messages to prevent information leakage
var (
	ErrInvalidPrivateKey = errors.New("invalid private key")
	ErrInvalidPublicKey  = errors.New("invalid public key")
	ErrInvalidSignature  = errors.New("invalid signature")
	ErrInvalidMessage    = errors.New("invalid message")
	ErrCryptoOperation   = errors.New("cryptographic operation failed")
)

// NewContext creates a new context for secp256k1 operations.
func NewContext() *Context {
	return &Context{}
}

// GeneratePrivateKey generates a new random private key.
func GeneratePrivateKey() (*PrivateKey, error) {
	// Limit attempts to prevent infinite loops
	for attempts := 0; attempts < 1000; attempts++ {
		// Generate 32 random bytes
		keyBytes := make([]byte, 32)
		if _, err := rand.Read(keyBytes); err != nil {
			return nil, ErrCryptoOperation
		}

		// Create scalar from bytes
		key := scalar.Zero()
		if key.SetBytes(keyBytes) && !key.IsZero() && key.IsLessThanOrder() {
			return &PrivateKey{key: key}, nil
		}
		// If the generated value is >= curve order or zero, try again
	}

	return nil, ErrCryptoOperation
}

// PrivateKeyFromBytes creates a private key from a 32-byte slice.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != 32 {
		return nil, ErrInvalidPrivateKey
	}

	key := scalar.Zero()
	if !key.SetBytes(b) || key.IsZero() {
		return nil, ErrInvalidPrivateKey
	}

	return &PrivateKey{key: key}, nil
}

// Bytes returns the private key as a 32-byte slice.
func (priv *PrivateKey) Bytes() []byte {
	if priv == nil || priv.key == nil {
		return make([]byte, 32) // Return zero bytes for nil private key
	}
	return priv.key.Bytes()
}

// Clear securely clears the private key from memory.
// This helps prevent memory dumps from revealing the private key.
func (priv *PrivateKey) Clear() {
	if priv == nil || priv.key == nil {
		return
	}

	// Clear the scalar using its own clear method
	priv.key.Clear()

	// Clear the private key reference
	priv.key = nil
}

// PublicKey derives the public key from the private key.
func (priv *PrivateKey) PublicKey() *PublicKey {
	// Compute pubkey = privkey * G
	g := group.Generator()
	pubPoint := group.Infinity().ScalarMult(priv.key, g)
	if !pubPoint.IsEven() {
		pubPoint = group.Infinity().Negate(pubPoint)
	}

	return &PublicKey{point: pubPoint}
}

// PublicKeyFromBytes creates a public key from a compressed 33-byte encoding.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != 33 {
		return nil, ErrInvalidPublicKey
	}

	point := group.Infinity()
	if !point.SetBytes(b) {
		return nil, ErrInvalidPublicKey
	}

	// Ensure the point is valid and not nil
	if point == nil {
		return nil, ErrInvalidPublicKey
	}

	return &PublicKey{point: point}, nil
}

// Bytes returns the compressed public key as a 33-byte slice.
func (pub *PublicKey) Bytes() []byte {
	if pub == nil || pub.point == nil {
		return make([]byte, 33) // Return zero bytes for nil public key
	}
	return pub.point.Bytes()
}

// XOnlyBytes returns the x-coordinate of the public key as a 32-byte slice.
// This is used for Schnorr signatures (BIP-340).
func (pub *PublicKey) XOnlyBytes() []byte {
	if pub == nil || pub.point == nil || pub.point.IsInfinity() {
		return make([]byte, 32)
	}

	// Get the x-coordinate
	xBytes := pub.point.X().Bytes()
	return xBytes
}

// IsEven returns true if the y-coordinate of the public key is even.
// This is used for Schnorr signatures (BIP-340).
func (pub *PublicKey) IsEven() bool {
	if pub.point.IsInfinity() {
		return true
	}

	yBytes := pub.point.Y().Bytes()
	return yBytes[31]&1 == 0
}

// SignECDSA creates an ECDSA signature for the given 32-byte message hash.
func (priv *PrivateKey) SignECDSA(msgHash []byte) (*Signature, error) {
	if len(msgHash) != 32 {
		return nil, ErrInvalidMessage
	}

	// Convert message hash to scalar
	e := scalar.Zero()
	if !e.SetBytes(msgHash) {
		return nil, ErrInvalidMessage
	}

	for {
		// Generate random nonce k
		k, err := generateNonce(priv.key, msgHash)
		if err != nil {
			return nil, err
		}

		// Compute R = k * G
		g := group.Generator()
		R := group.Infinity().ScalarMult(k, g)

		if R.IsInfinity() {
			continue // Try again with different nonce
		}

		// r = R.x mod n
		r := scalar.Zero()
		rBytes := R.X().Bytes()
		if !r.SetBytes(rBytes) || r.IsZero() {
			continue // Try again with different nonce
		}

		// s = k^(-1) * (e + r * privkey) mod n
		kInv := scalar.Zero().Inverse(k)
		rd := scalar.Zero().Mul(r, priv.key)
		ePlusRd := scalar.Zero().Add(e, rd)
		s := scalar.Zero().Mul(ePlusRd, kInv)

		if s.IsZero() {
			continue // Try again with different nonce
		}

		return &Signature{r: r, s: s}, nil
	}
}

// VerifyECDSA verifies an ECDSA signature against the given message hash.
func (pub *PublicKey) VerifyECDSA(sig *Signature, msgHash []byte) bool {
	if len(msgHash) != 32 {
		return false
	}

	// Check signature components are valid
	if sig.r.IsZero() || sig.s.IsZero() {
		return false
	}

	// Convert message hash to scalar
	e := scalar.Zero()
	if !e.SetBytes(msgHash) {
		return false
	}

	// Compute u1 = e * s^(-1) mod n
	sInv := scalar.Zero().Inverse(sig.s)
	u1 := scalar.Zero().Mul(e, sInv)

	// Compute u2 = r * s^(-1) mod n
	u2 := scalar.Zero().Mul(sig.r, sInv)

	// Compute point = u1 * G + u2 * pubkey
	g := group.Generator()
	point1 := group.Infinity().ScalarMult(u1, g)
	point2 := group.Infinity().ScalarMult(u2, pub.point)
	point := group.Infinity().Add(point1, point2)

	if point.IsInfinity() {
		return false
	}

	// Check if point.x == r mod n
	pointX := scalar.Zero()
	xBytes := point.X().Bytes()
	if !pointX.SetBytes(xBytes) {
		return false
	}

	return pointX.Equal(sig.r)
}

// generateNonce generates a deterministic nonce using RFC 6979.
// This implements the deterministic nonce generation algorithm from RFC 6979.
func generateNonce(privkey *scalar.Scalar, msgHash []byte) (*scalar.Scalar, error) {
	// RFC 6979 deterministic nonce generation
	privkeyBytes := privkey.Bytes()

	// Initialize V = 0x01...01 (32 bytes)
	V := make([]byte, 32)
	for i := range V {
		V[i] = 0x01
	}

	// Initialize K = 0x00...00 (32 bytes)
	K := make([]byte, 32)

	// Step 1: K = HMAC-SHA256(K, V || 0x00 || privkey || msgHash)
	data := make([]byte, 0, len(V)+1+len(privkeyBytes)+len(msgHash))
	data = append(data, V...)
	data = append(data, 0x00)
	data = append(data, privkeyBytes...)
	data = append(data, msgHash...)
	h := hmac.New(sha256.New, K)
	h.Write(data)
	K = h.Sum(nil)

	// Step 2: V = HMAC-SHA256(K, V)
	h = hmac.New(sha256.New, K)
	h.Write(V)
	V = h.Sum(nil)

	// Step 3: K = HMAC-SHA256(K, V || 0x01 || privkey || msgHash)
	data = make([]byte, 0, len(V)+1+len(privkeyBytes)+len(msgHash))
	data = append(data, V...)
	data = append(data, 0x01)
	data = append(data, privkeyBytes...)
	data = append(data, msgHash...)
	h = hmac.New(sha256.New, K)
	h.Write(data)
	K = h.Sum(nil)

	// Step 4: V = HMAC-SHA256(K, V)
	h = hmac.New(sha256.New, K)
	h.Write(V)
	V = h.Sum(nil)

	// Generate candidate nonce
	return generateNonceCandidate(K, V, privkeyBytes, msgHash)
}

// generateNonceCandidate generates a candidate nonce when the first attempt fails.
func generateNonceCandidate(K, V, privkeyBytes, msgHash []byte) (*scalar.Scalar, error) {
	// Generate up to 1000 candidates (RFC 6979 limit)
	for i := 0; i < 1000; i++ {
		// K = HMAC-SHA256(K, V)
		h := hmac.New(sha256.New, K)
		h.Write(V)
		K = h.Sum(nil)

		// V = HMAC-SHA256(K, V)
		h = hmac.New(sha256.New, K)
		h.Write(V)
		V = h.Sum(nil)

		// T = HMAC-SHA256(K, V)
		h = hmac.New(sha256.New, K)
		h.Write(V)
		T := h.Sum(nil)

		// Convert T to scalar
		k := scalar.Zero()
		if k.SetBytes(T) && !k.IsZero() && k.IsLessThanOrder() {
			return k, nil
		}
	}

	return nil, errors.New("failed to generate valid nonce after 1000 attempts")
}

// SignatureFromBytes creates a signature from a 64-byte DER encoding.
// This is a simplified implementation.
func SignatureFromBytes(b []byte) (*Signature, error) {
	if len(b) != 64 {
		return nil, ErrInvalidSignature
	}

	r := scalar.Zero()
	s := scalar.Zero()

	if !r.SetBytes(b[:32]) || !s.SetBytes(b[32:]) {
		return nil, ErrInvalidSignature
	}

	if r.IsZero() || s.IsZero() {
		return nil, ErrInvalidSignature
	}

	return &Signature{r: r, s: s}, nil
}

// Bytes returns the signature as a 64-byte slice (r || s).
func (sig *Signature) Bytes() []byte {
	result := make([]byte, 64)
	copy(result[:32], sig.r.Bytes())
	copy(result[32:], sig.s.Bytes())
	return result
}
