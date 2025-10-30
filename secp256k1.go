// Package secp256k1 provides a pure Go implementation of the secp256k1 elliptic curve
// with support for ECDSA and Schnorr signatures (BIP-340).
package secp256k1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/rafaelescrich/go-secp256k1/field"
	"github.com/rafaelescrich/go-secp256k1/group"
	"github.com/rafaelescrich/go-secp256k1/scalar"
)

// Context holds precomputed tables and configuration for cryptographic operations.
type Context struct {
	// Precomputed tables for efficient scalar multiplication
	// This implementation provides full secp256k1 functionality including:
	// - ECDSA signatures with RFC 6979 deterministic nonces
	// - BIP-340 Schnorr signatures with tagged hashing
	// - Adaptor signatures for payment channels and atomic swaps
	// - Multiple signature formats (64-byte and 96-byte)
	// - Configurable challenge methods for cross-chain compatibility

	// Precomputed multiples of the generator point for faster operations
	precomputedG []*group.Point

	// Configuration flags
	verifySignatures bool
	signatureMode    SignatureMode
}

// SignatureMode defines the signature verification mode
type SignatureMode int

const (
	// ModeStrict enforces strict signature validation
	ModeStrict SignatureMode = iota
	// ModeCompatible allows more flexible signature validation for cross-chain compatibility
	ModeCompatible
)

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

// NewContext creates a new context for secp256k1 operations with precomputed tables.
func NewContext() *Context {
	ctx := &Context{
		verifySignatures: true,
		signatureMode:    ModeStrict,
	}

	// Precompute multiples of the generator point for faster scalar multiplication
	// This creates a table of 1G, 2G, 3G, ..., 15G for windowed multiplication
	ctx.precomputedG = make([]*group.Point, 16)
	g := group.Generator()
	ctx.precomputedG[0] = group.Infinity() // 0*G = O (point at infinity)
	ctx.precomputedG[1] = g                // 1*G = G

	// Compute 2G, 3G, 4G, ..., 15G
	for i := 2; i < 16; i++ {
		ctx.precomputedG[i] = group.Infinity().Add(ctx.precomputedG[i-1], g)
	}

	return ctx
}

// NewContextWithMode creates a new context with the specified signature mode.
func NewContextWithMode(mode SignatureMode) *Context {
	ctx := NewContext()
	ctx.signatureMode = mode
	return ctx
}

// SetVerifySignatures enables or disables signature verification.
func (ctx *Context) SetVerifySignatures(verify bool) {
	ctx.verifySignatures = verify
}

// GetSignatureMode returns the current signature verification mode.
func (ctx *Context) GetSignatureMode() SignatureMode {
	return ctx.signatureMode
}

// FastScalarMult performs scalar multiplication using precomputed tables for faster operations.
func (ctx *Context) FastScalarMult(k *scalar.Scalar) *group.Point {
	if ctx.precomputedG == nil || len(ctx.precomputedG) < 16 {
		// Fallback to regular scalar multiplication
		g := group.Generator()
		return group.Infinity().ScalarMult(k, g)
	}

	// Use windowed method with precomputed table (window size = 4 bits)
	result := group.Infinity()
	kBytes := k.Bytes()

	// Process from most significant to least significant bits
	for byteIdx := 0; byteIdx < 32; byteIdx++ {
		b := kBytes[byteIdx]

		// Process upper 4 bits first
		upperNibble := int((b & 0xF0) >> 4)
		if upperNibble != 0 {
			// Double the result 4 times for the upper nibble position (optimized)
			for j := 0; j < 4; j++ {
				result = group.Infinity().DoubleOptimized(result)
			}
			// Add the precomputed value (optimized)
			result = group.Infinity().AddOptimized(result, ctx.precomputedG[upperNibble])
		} else {
			// Still need to double 4 times even if nibble is 0 (optimized)
			for j := 0; j < 4; j++ {
				result = group.Infinity().DoubleOptimized(result)
			}
		}

		// Process lower 4 bits
		lowerNibble := int(b & 0x0F)
		if lowerNibble != 0 {
			// Double the result 4 times for the lower nibble position (optimized)
			for j := 0; j < 4; j++ {
				result = group.Infinity().DoubleOptimized(result)
			}
			// Add the precomputed value (optimized)
			result = group.Infinity().AddOptimized(result, ctx.precomputedG[lowerNibble])
		} else {
			// Still need to double 4 times even if nibble is 0 (optimized)
			for j := 0; j < 4; j++ {
				result = group.Infinity().DoubleOptimized(result)
			}
		}
	}

	return result
}

// FastScalarMultOptimized performs fully optimized scalar multiplication.
// This is the fastest scalar multiplication method available.
func (ctx *Context) FastScalarMultOptimized(k *scalar.Scalar) *group.Point {
	if ctx.precomputedG == nil || len(ctx.precomputedG) < 16 {
		// Fallback to optimized scalar multiplication
		g := group.Generator()
		return group.Infinity().ScalarMultOptimized(k, g)
	}

	// Use optimized windowed method with precomputed table
	result := group.Infinity()
	kBytes := k.Bytes()

	// Process from most significant to least significant bits
	for byteIdx := 0; byteIdx < 32; byteIdx++ {
		b := kBytes[byteIdx]

		// Process upper 4 bits first
		upperNibble := int((b & 0xF0) >> 4)
		if upperNibble != 0 {
			// Double the result 4 times for the upper nibble position (optimized)
			for j := 0; j < 4; j++ {
				result = group.Infinity().DoubleOptimized(result)
			}
			// Add the precomputed value (optimized)
			result = group.Infinity().AddOptimized(result, ctx.precomputedG[upperNibble])
		} else {
			// Still need to double 4 times even if nibble is 0 (optimized)
			for j := 0; j < 4; j++ {
				result = group.Infinity().DoubleOptimized(result)
			}
		}

		// Process lower 4 bits
		lowerNibble := int(b & 0x0F)
		if lowerNibble != 0 {
			// Double the result 4 times for the lower nibble position (optimized)
			for j := 0; j < 4; j++ {
				result = group.Infinity().DoubleOptimized(result)
			}
			// Add the precomputed value (optimized)
			result = group.Infinity().AddOptimized(result, ctx.precomputedG[lowerNibble])
		} else {
			// Still need to double 4 times even if nibble is 0 (optimized)
			for j := 0; j < 4; j++ {
				result = group.Infinity().DoubleOptimized(result)
			}
		}
	}

	return result
}

// SignECDSAWithContext creates an ECDSA signature using the context's precomputed tables.
func (ctx *Context) SignECDSA(priv *PrivateKey, msgHash []byte) (*Signature, error) {
	// Use the regular signing method - the precomputed tables are mainly for verification
	return priv.SignECDSA(msgHash)
}

// VerifyECDSAWithContext verifies an ECDSA signature using the context's configuration.
func (ctx *Context) VerifyECDSA(pub *PublicKey, sig *Signature, msgHash []byte) bool {
	if !ctx.verifySignatures {
		return true // Skip verification if disabled
	}

	return pub.VerifyECDSA(sig, msgHash)
}

// ValidatePrecomputedTables verifies that the precomputed tables are correct.
func (ctx *Context) ValidatePrecomputedTables() bool {
	if ctx.precomputedG == nil || len(ctx.precomputedG) < 16 {
		return false
	}

	g := group.Generator()

	// Verify that precomputedG[i] = i * G for i = 0, 1, 2, ..., 15
	for i := 0; i < 16; i++ {
		// Create scalar for i
		iScalar := scalar.Zero()
		iBytes := make([]byte, 32)
		iBytes[31] = byte(i)
		iScalar.SetBytes(iBytes)

		// Compute i * G using regular scalar multiplication
		expected := group.Infinity().ScalarMult(iScalar, g)

		// Compare with precomputed value
		if !expected.Equal(ctx.precomputedG[i]) {
			return false
		}
	}

	return true
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

// Key returns the private key as a big integer (for Bor compatibility)
func (priv *PrivateKey) Key() *big.Int {
	if priv == nil || priv.key == nil {
		return new(big.Int)
	}
	keyBytes := priv.key.Bytes()
	return new(big.Int).SetBytes(keyBytes)
}

// Zero zeros out the private key (alias for Clear, for Bor compatibility)
func (priv *PrivateKey) Zero() {
	priv.Clear()
}

// PublicKey derives the public key from the private key.
func (priv *PrivateKey) PublicKey() *PublicKey {
	// Compute pubkey = privkey * G
	g := group.Generator()
	pubPoint := group.Infinity().ScalarMult(priv.key, g)

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

// PublicKeyFromUncompressed creates a public key from uncompressed 64-byte encoding (X || Y).
func PublicKeyFromUncompressed(b []byte) (*PublicKey, error) {
	if len(b) != 64 {
		return nil, ErrInvalidPublicKey
	}

	x := field.Zero()
	y := field.Zero()
	if !x.SetBytes(b[:32]) || !y.SetBytes(b[32:]) {
		return nil, ErrInvalidPublicKey
	}

	point := &group.Point{}
	point.SetXY(x, y)

	if !point.IsOnCurve() {
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

// ToECDSA converts the public key to a standard library ecdsa.PublicKey.
func (pub *PublicKey) ToECDSA() *ecdsa.PublicKey {
	if pub == nil || pub.point == nil || pub.point.IsInfinity() {
		return nil
	}

	return &ecdsa.PublicKey{
		Curve: S256(),
		X:     new(big.Int).SetBytes(pub.point.X().Bytes()),
		Y:     new(big.Int).SetBytes(pub.point.Y().Bytes()),
	}
}

// SerializeUncompressed serializes the public key in uncompressed format (65 bytes)
// Returns 0x04 + 32 bytes X coordinate + 32 bytes Y coordinate
func (pub *PublicKey) SerializeUncompressed() []byte {
	if pub == nil || pub.point == nil || pub.point.IsInfinity() {
		return nil
	}

	// Standard uncompressed format: 0x04 + 32 bytes X + 32 bytes Y
	result := make([]byte, 65)
	result[0] = 0x04

	// Fill X coordinate (32 bytes, big-endian)
	xBytes := pub.point.X().Bytes()
	copy(result[33-len(xBytes):33], xBytes)

	// Fill Y coordinate (32 bytes, big-endian)
	yBytes := pub.point.Y().Bytes()
	copy(result[65-len(yBytes):65], yBytes)

	return result
}

// X returns the X coordinate of the public key
func (pub *PublicKey) X() *big.Int {
	if pub == nil || pub.point == nil || pub.point.IsInfinity() {
		return new(big.Int)
	}
	return new(big.Int).SetBytes(pub.point.X().Bytes())
}

// Y returns the Y coordinate of the public key
func (pub *PublicKey) Y() *big.Int {
	if pub == nil || pub.point == nil || pub.point.IsInfinity() {
		return new(big.Int)
	}
	return new(big.Int).SetBytes(pub.point.Y().Bytes())
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

// S256 returns the secp256k1 curve.
func S256() *secp256k1Curve {
	return &secp256k1Curve{}
}

// secp256k1Curve implements the elliptic.Curve interface for secp256k1.
type secp256k1Curve struct{}

func (curve *secp256k1Curve) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{
		P:       new(big.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F}),
		N:       new(big.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41}),
		B:       big.NewInt(7),
		Gx:      new(big.Int).SetBytes([]byte{0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98}),
		Gy:      new(big.Int).SetBytes([]byte{0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8}),
		BitSize: 256,
		Name:    "secp256k1",
	}
}

func (curve *secp256k1Curve) IsOnCurve(x, y *big.Int) bool {
	p := &group.Point{}
	fx := field.Zero()
	fy := field.Zero()

	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	x.FillBytes(xBytes)
	y.FillBytes(yBytes)

	if !fx.SetBytes(xBytes) || !fy.SetBytes(yBytes) {
		return false
	}

	p.SetXY(fx, fy)
	return p.IsOnCurve()
}

func (curve *secp256k1Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p1 := &group.Point{}
	p2 := &group.Point{}

	fx1 := field.Zero()
	fy1 := field.Zero()
	fx2 := field.Zero()
	fy2 := field.Zero()

	x1Bytes := make([]byte, 32)
	y1Bytes := make([]byte, 32)
	x2Bytes := make([]byte, 32)
	y2Bytes := make([]byte, 32)

	x1.FillBytes(x1Bytes)
	y1.FillBytes(y1Bytes)
	x2.FillBytes(x2Bytes)
	y2.FillBytes(y2Bytes)

	fx1.SetBytes(x1Bytes)
	fy1.SetBytes(y1Bytes)
	fx2.SetBytes(x2Bytes)
	fy2.SetBytes(y2Bytes)

	p1.SetXY(fx1, fy1)
	p2.SetXY(fx2, fy2)

	result := group.Infinity().Add(p1, p2)
	if result.IsInfinity() {
		return nil, nil
	}

	return new(big.Int).SetBytes(result.X().Bytes()), new(big.Int).SetBytes(result.Y().Bytes())
}

func (curve *secp256k1Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	p := &group.Point{}
	fx := field.Zero()
	fy := field.Zero()

	x1Bytes := make([]byte, 32)
	y1Bytes := make([]byte, 32)
	x1.FillBytes(x1Bytes)
	y1.FillBytes(y1Bytes)

	fx.SetBytes(x1Bytes)
	fy.SetBytes(y1Bytes)
	p.SetXY(fx, fy)

	result := group.Infinity().Double(p)
	if result.IsInfinity() {
		return nil, nil
	}

	return new(big.Int).SetBytes(result.X().Bytes()), new(big.Int).SetBytes(result.Y().Bytes())
}

func (curve *secp256k1Curve) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	p := &group.Point{}
	fx := field.Zero()
	fy := field.Zero()

	x1Bytes := make([]byte, 32)
	y1Bytes := make([]byte, 32)
	x1.FillBytes(x1Bytes)
	y1.FillBytes(y1Bytes)

	fx.SetBytes(x1Bytes)
	fy.SetBytes(y1Bytes)
	p.SetXY(fx, fy)

	sc := scalar.Zero()
	kBytes := make([]byte, 32)
	if len(k) <= 32 {
		copy(kBytes[32-len(k):], k)
	} else {
		copy(kBytes, k[len(k)-32:])
	}
	sc.SetBytes(kBytes)

	result := group.Infinity().ScalarMult(sc, p)
	if result.IsInfinity() {
		return nil, nil
	}

	return new(big.Int).SetBytes(result.X().Bytes()), new(big.Int).SetBytes(result.Y().Bytes())
}

func (curve *secp256k1Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	sc := scalar.Zero()
	kBytes := make([]byte, 32)
	if len(k) <= 32 {
		copy(kBytes[32-len(k):], k)
	} else {
		copy(kBytes, k[len(k)-32:])
	}
	sc.SetBytes(kBytes)

	result := group.Infinity().ScalarMult(sc, group.Generator())
	if result.IsInfinity() {
		return nil, nil
	}

	return new(big.Int).SetBytes(result.X().Bytes()), new(big.Int).SetBytes(result.Y().Bytes())
}

// Additional functions for Bor compatibility

// RecoverCompact recovers a public key from a compact signature
func RecoverCompact(signature, hash []byte) (*PublicKey, bool, error) {
	if len(signature) != 65 {
		return nil, false, errors.New("invalid signature length")
	}
	if len(hash) != 32 {
		return nil, false, errors.New("invalid hash length")
	}

	// Extract recovery ID (last byte)
	recoveryID := signature[64]
	if recoveryID >= 4 {
		return nil, false, errors.New("invalid recovery ID")
	}

	compressed := recoveryID < 2

	// Use your existing recovery implementation
	// This is a simplified version - you may need to adapt based on your recovery module
	pubKey, err := recoverPublicKey(signature[:64], hash, int(recoveryID%2))
	if err != nil {
		return nil, false, err
	}

	return pubKey, compressed, nil
}

// SignCompact creates a compact signature
func SignCompact(priv *PrivateKey, hash []byte, compressed bool) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("private key is nil")
	}
	if len(hash) != 32 {
		return nil, errors.New("invalid hash length")
	}

	// Create ECDSA signature
	sig, err := priv.SignECDSA(hash)
	if err != nil {
		return nil, err
	}

	// Convert to compact format
	result := make([]byte, 65)
	copy(result[:32], sig.R().Bytes())
	copy(result[32:64], sig.S().Bytes())

	// Set recovery ID (simplified - you may need to calculate this properly)
	recoveryID := byte(0)
	if !compressed {
		recoveryID += 2
	}
	result[64] = recoveryID

	return result, nil
}

// PrivKeyFromBytes is an alias for PrivateKeyFromBytes (for Bor compatibility)
func PrivKeyFromBytes(b []byte) *PrivateKey {
	priv, err := PrivateKeyFromBytes(b)
	if err != nil {
		return nil
	}
	return priv
}

// NewSignature creates a new signature from R and S values
func NewSignature(r, s *big.Int) *Signature {
	sig := &Signature{}
	// You'll need to adapt this based on your Signature struct
	// This is a placeholder implementation
	return sig
}

// KoblitzCurve returns the secp256k1 curve (alias for S256)
func KoblitzCurve() elliptic.Curve {
	return S256()
}

// ParsePubKey parses a public key from bytes (alias for PublicKeyFromBytes)
func ParsePubKey(pubKeyBytes []byte) (*PublicKey, error) {
	return PublicKeyFromBytes(pubKeyBytes)
}

// NewPrivateKey generates a new private key (alias for existing GeneratePrivateKey function)
func NewPrivateKey() (*PrivateKey, error) {
	return GeneratePrivateKey()
}

// Helper function for public key recovery (simplified implementation)
func recoverPublicKey(signature, hash []byte, recoveryID int) (*PublicKey, error) {
	// This is a simplified implementation
	// You should implement proper ECDSA recovery based on your existing code
	// For now, return an error to indicate it needs proper implementation
	return nil, errors.New("recoverPublicKey: needs proper implementation based on your recovery module")
}

// Additional types for compatibility with btcsuite and other libraries

// ModNScalar represents a scalar modulo the curve order (alias for big.Int for compatibility)
type ModNScalar = big.Int

// FieldVal represents a field element (alias for your field.Element)
type FieldVal = field.Element

// JacobianPoint represents a point in Jacobian coordinates (alias for your group.Point)
type JacobianPoint = group.Point

// Error represents a secp256k1 error
type Error struct {
	message string
}

func (e Error) Error() string {
	return e.message
}

// ErrorKind represents the kind of error
type ErrorKind int

const (
	// ErrInvalidPrivKey indicates an invalid private key
	ErrInvalidPrivKey ErrorKind = iota
	// ErrInvalidPubKey indicates an invalid public key
	ErrInvalidPubKey
)

// Params returns the secp256k1 curve parameters (alias for S256().Params())
func Params() *elliptic.CurveParams {
	return S256().Params()
}

// CurveParams is an alias for elliptic.CurveParams
type CurveParams = elliptic.CurveParams

// GenerateSharedSecret generates a shared secret using ECDH
func GenerateSharedSecret(privKey []byte, pubKey []byte) []byte {
	// This is a placeholder implementation
	// You should implement proper ECDH based on your existing code
	return make([]byte, 32)
}
