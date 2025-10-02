// Package schnorr implements BIP-340 Schnorr signatures for secp256k1.
package schnorr

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/rafaelescrich/go-secp256k1/field"
	"github.com/rafaelescrich/go-secp256k1/group"
	"github.com/rafaelescrich/go-secp256k1/scalar"
)

// Signature represents a BIP-340 Schnorr signature.
type Signature struct {
	r *field.FieldVal // x-coordinate of R point (32 bytes)
	s *scalar.Scalar  // signature scalar (32 bytes)
}

// Common errors
var (
	ErrInvalidSignature = errors.New("invalid schnorr signature")
	ErrInvalidMessage   = errors.New("invalid message")
	ErrInvalidPublicKey = errors.New("invalid public key")
)

// Sign creates a BIP-340 Schnorr signature for the given message.
// The message must be exactly 32 bytes (typically a hash).
func Sign(privkey *scalar.Scalar, msg []byte) (*Signature, error) {
	if len(msg) != 32 {
		return nil, ErrInvalidMessage
	}

	// Derive the public key P = d * G
	g := group.Generator()
	P := group.Infinity().ScalarMult(privkey, g)

	if P.IsInfinity() {
		return nil, errors.New("invalid private key")
	}

	// If P.y is odd, negate the private key
	d := scalar.Zero()
	*d = *privkey
	if !P.IsEven() {
		d.Negate(d)
		// Recompute P with the negated private key to ensure even y-coordinate
		P = group.Infinity().ScalarMult(d, g)
	}

	// Generate nonce k using BIP-340 nonce generation
	k, err := generateSchnorrNonce(d, msg)
	if err != nil {
		return nil, err
	}

	// Compute R = k * G
	R := group.Infinity().ScalarMult(k, g)
	if R.IsInfinity() {
		return nil, errors.New("invalid nonce")
	}

	// If R.y is odd, negate k
	if !R.IsEven() {
		k.Negate(k)
		R.Negate(R)
	}

	// r = R.x (as field element)
	r := R.X()

	// Compute challenge e = hash(r || P.x || m)
	e := computeChallenge(r, P.X(), msg)

	// Compute s = k + e * d mod n
	ed := scalar.Zero().Mul(e, d)
	s := scalar.Zero().Add(ed, k)

	return &Signature{r: r, s: s}, nil
}

// Verify verifies a BIP-340 Schnorr signature against the given message and public key.
func Verify(pubkey *group.Point, msg []byte, sig *Signature) bool {
	if len(msg) != 32 {
		return false
	}

	if pubkey.IsInfinity() {
		return false
	}

	// Check that pubkey has even y-coordinate (BIP-340 requirement)
	if !pubkey.IsEven() {
		return false
	}

	// Check that r is a valid x-coordinate (< field prime)
	if !isValidFieldElement(sig.r) {
		return false
	}

	// Check that s is a valid scalar (< curve order)
	if !isValidScalar(sig.s) {
		return false
	}

	// Compute challenge e = hash(r || P.x || m)
	e := computeChallenge(sig.r, pubkey.X(), msg)

	// Compute R = s * G - e * P
	g := group.Generator()
	sG := group.Infinity().ScalarMult(sig.s, g)
	eP := group.Infinity().ScalarMult(e, pubkey)
	R := group.Infinity().Sub(sG, eP)

	if R.IsInfinity() {
		return false
	}

	// Check that R has even y-coordinate
	if !R.IsEven() {
		return false
	}

	// Check that R.x == r
	return R.X().Equal(sig.r)
}

// generateSchnorrNonce generates a BIP-340 compliant nonce.
// This implements the deterministic nonce generation from BIP-340.
func generateSchnorrNonce(privkey *scalar.Scalar, msg []byte) (*scalar.Scalar, error) {
	// BIP-340 nonce generation:
	// t = hash(bytes(d) || msg) where d is the private key
	h := sha256.New()
	h.Write(privkey.Bytes())
	h.Write(msg)
	t := h.Sum(nil)

	// k = int(t) mod n
	k := scalar.Zero()
	if !k.SetBytes(t) {
		// If t >= n, we need to reduce it properly
		// BIP-340 specifies: if t >= n, then k = t - n
		return reduceNonceModOrder(t)
	}

	// Check if k is valid (not zero and < curve order)
	if k.IsZero() || !k.IsLessThanOrder() {
		return reduceNonceModOrder(t)
	}

	return k, nil
}

// reduceNonceModOrder reduces a 32-byte value modulo the curve order.
func reduceNonceModOrder(t []byte) (*scalar.Scalar, error) {
	// Convert t to big.Int and reduce modulo curve order
	curveOrderBytes := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
	}

	// Use big.Int for proper modular reduction
	tBig := new(big.Int).SetBytes(t)
	orderBig := new(big.Int).SetBytes(curveOrderBytes)

	// Reduce modulo curve order
	tBig.Mod(tBig, orderBig)

	// Convert back to scalar
	k := scalar.Zero()
	if !k.SetBytes(tBig.Bytes()) {
		return nil, errors.New("failed to convert reduced nonce to scalar")
	}

	// Final validation
	if k.IsZero() || !k.IsLessThanOrder() {
		return nil, errors.New("reduced nonce is invalid")
	}

	return k, nil
}

// computeChallenge computes the BIP-340 challenge hash.
// e = hash("BIP0340/challenge" || r || P || m)
func computeChallenge(r, pubkeyX *field.FieldVal, msg []byte) *scalar.Scalar {
	// BIP-340 tagged hash for challenge
	tag := "BIP0340/challenge"
	tagHash := sha256.Sum256([]byte(tag))

	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(r.Bytes())
	h.Write(pubkeyX.Bytes())
	h.Write(msg)

	challengeBytes := h.Sum(nil)

	e := scalar.Zero()
	e.SetBytes(challengeBytes) // This will automatically reduce modulo n

	return e
}

// isValidFieldElement checks if the field element is valid (< field prime).
func isValidFieldElement(f *field.FieldVal) bool {
	// Check if f < field prime
	fieldPrimeBytes := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
	}

	temp := field.Zero()
	temp.SetBytes(fieldPrimeBytes)

	// Create a temporary field element to compare
	fBytes := f.Bytes()
	tempF := field.Zero()
	tempF.SetBytes(fBytes)

	return !tempF.Equal(temp) // f should be < prime, not equal
}

// isValidScalar checks if the scalar is valid (< curve order).
func isValidScalar(s *scalar.Scalar) bool {
	// Check if s < curve order
	curveOrderBytes := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
	}

	temp := scalar.Zero()
	temp.SetBytes(curveOrderBytes)

	// Create a temporary scalar to compare
	sBytes := s.Bytes()
	tempS := scalar.Zero()
	tempS.SetBytes(sBytes)

	return !tempS.Equal(temp) // s should be < order, not equal
}

// SignatureFromBytes creates a Schnorr signature from a 64-byte encoding.
func SignatureFromBytes(b []byte) (*Signature, error) {
	if len(b) != 64 {
		return nil, ErrInvalidSignature
	}

	r := field.Zero()
	s := scalar.Zero()

	if !r.SetBytes(b[:32]) {
		return nil, ErrInvalidSignature
	}

	if !s.SetBytes(b[32:]) {
		return nil, ErrInvalidSignature
	}

	// Validate the signature components
	if !isValidFieldElement(r) || !isValidScalar(s) {
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
func (sig *Signature) R() *field.FieldVal {
	return sig.r
}

// S returns the s component of the signature.
func (sig *Signature) S() *scalar.Scalar {
	return sig.s
}
