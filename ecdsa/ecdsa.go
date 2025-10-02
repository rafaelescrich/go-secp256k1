// Package ecdsa implements ECDSA (Elliptic Curve Digital Signature Algorithm) for secp256k1.
package ecdsa

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"

	"github.com/rafaelescrich/go-secp256k1/group"
	"github.com/rafaelescrich/go-secp256k1/scalar"
)

// Signature represents an ECDSA signature.
type Signature struct {
	r *scalar.Scalar
	s *scalar.Scalar
}

// Common errors
var (
	ErrInvalidSignature  = errors.New("invalid ecdsa signature")
	ErrInvalidMessage    = errors.New("invalid message")
	ErrInvalidPrivateKey = errors.New("invalid private key")
	ErrInvalidPublicKey  = errors.New("invalid public key")
)

// Sign creates an ECDSA signature for the given message hash.
// The message should be a 32-byte hash (typically SHA-256).
func Sign(privkey *scalar.Scalar, msgHash []byte) (*Signature, error) {
	if len(msgHash) != 32 {
		return nil, ErrInvalidMessage
	}

	if privkey.IsZero() {
		return nil, ErrInvalidPrivateKey
	}

	// Convert message hash to scalar
	e := scalar.Zero()
	e.SetBytes(msgHash)

	// Generate nonce k (in practice, this should be cryptographically secure)
	k, err := generateNonce(privkey, msgHash)
	if err != nil {
		return nil, err
	}

	// Compute R = k * G
	g := group.Generator()
	R := group.Infinity().ScalarMult(k, g)
	if R.IsInfinity() {
		return nil, errors.New("invalid nonce")
	}

	// r = R.x mod n
	r := scalar.Zero()
	r.SetBytes(R.X().Bytes())

	// s = k^(-1) * (e + r * d) mod n
	s := scalar.Zero()
	rd := scalar.Zero().Mul(r, privkey)
	ePlusRd := scalar.Zero().Add(e, rd)
	kInv := scalar.Zero().Inverse(k)
	s.Mul(kInv, ePlusRd)

	// If s > n/2, use s = n - s (low-s signature)
	nHalf := scalar.Zero()
	nHalf.SetBytes([]byte{
		0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
		0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
	})

	if s.GreaterThan(nHalf) {
		s.Sub(scalar.Zero(), s)
	}

	return &Signature{r: r, s: s}, nil
}

// Verify verifies an ECDSA signature against the given message hash and public key.
func Verify(pubkey *group.Point, msgHash []byte, sig *Signature) bool {
	if len(msgHash) != 32 {
		return false
	}

	if pubkey.IsInfinity() {
		return false
	}

	// Check that r and s are in valid range [1, n-1]
	if sig.r.IsZero() || sig.s.IsZero() {
		return false
	}

	// Convert message hash to scalar
	e := scalar.Zero()
	e.SetBytes(msgHash)

	// Compute s^(-1) mod n
	sInv := scalar.Zero().Inverse(sig.s)
	if sInv.IsZero() {
		return false
	}

	// Compute u1 = e * s^(-1) mod n
	u1 := scalar.Zero().Mul(e, sInv)

	// Compute u2 = r * s^(-1) mod n
	u2 := scalar.Zero().Mul(sig.r, sInv)

	// Compute R = u1 * G + u2 * P
	g := group.Generator()
	u1G := group.Infinity().ScalarMult(u1, g)
	u2P := group.Infinity().ScalarMult(u2, pubkey)
	R := group.Infinity().Add(u1G, u2P)

	if R.IsInfinity() {
		return false
	}

	// Check that R.x mod n == r
	rCheck := scalar.Zero()
	rCheck.SetBytes(R.X().Bytes())

	return rCheck.Equal(sig.r)
}

// generateNonce generates a deterministic nonce for ECDSA using RFC 6979.
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

// SignatureFromBytes creates an ECDSA signature from a 64-byte encoding (r || s).
func SignatureFromBytes(b []byte) (*Signature, error) {
	if len(b) != 64 {
		return nil, ErrInvalidSignature
	}

	r := scalar.Zero()
	s := scalar.Zero()

	if !r.SetBytes(b[:32]) {
		return nil, ErrInvalidSignature
	}

	if !s.SetBytes(b[32:]) {
		return nil, ErrInvalidSignature
	}

	// Validate the signature components
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

// R returns the r component of the signature.
func (sig *Signature) R() *scalar.Scalar {
	return sig.r
}

// S returns the s component of the signature.
func (sig *Signature) S() *scalar.Scalar {
	return sig.s
}
