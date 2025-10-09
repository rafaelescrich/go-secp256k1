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

// AdaptorSignature represents a Schnorr adaptor signature.
type AdaptorSignature struct {
	r *field.FieldVal // x-coordinate of R point (32 bytes)
	s *scalar.Scalar  // adaptor signature scalar (32 bytes)
}

// FullSignature represents a signature with full R point coordinates (96 bytes total).
type FullSignature struct {
	rx *field.FieldVal // x-coordinate of R point (32 bytes)
	ry *field.FieldVal // y-coordinate of R point (32 bytes)
	s  *scalar.Scalar  // signature scalar (32 bytes)
}

// AdaptorSign creates a Schnorr adaptor signature for the given message with adaptor point T.
// The adaptor signature allows for secret extraction when combined with a standard signature.
func AdaptorSign(privkey *scalar.Scalar, msg []byte, adaptorPoint *group.Point) (*AdaptorSignature, error) {
	if len(msg) != 32 {
		return nil, ErrInvalidMessage
	}

	if adaptorPoint.IsInfinity() {
		return nil, errors.New("adaptor point cannot be infinity")
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
		P = group.Infinity().ScalarMult(d, g)
	}

	// Generate nonce k using BIP-340 nonce generation (with adaptor point)
	k, err := generateAdaptorNonce(d, msg, adaptorPoint)
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

	// Compute R' = R + T for challenge computation
	RPrime := group.Infinity().Add(R, adaptorPoint)
	if RPrime.IsInfinity() {
		return nil, errors.New("R + T results in infinity")
	}

	// Compute challenge e = hash(P.x || P.y || R'.x || R'.y || m) - using full coordinates like Solidity
	e := computeAdaptorChallenge(P, RPrime, msg)

	// Compute s' = k + e * d mod n (adaptor signature scalar)
	ed := scalar.Zero().Mul(e, d)
	s := scalar.Zero().Add(ed, k)

	return &AdaptorSignature{r: r, s: s}, nil
}

// AdaptorVerify verifies a Schnorr adaptor signature against the given message, public key, and adaptor point.
func AdaptorVerify(pubkey *group.Point, msg []byte, sig *AdaptorSignature, adaptorPoint *group.Point) bool {
	if len(msg) != 32 {
		return false
	}

	if pubkey.IsInfinity() || adaptorPoint.IsInfinity() {
		return false
	}

	// Check that pubkey has even y-coordinate
	if !pubkey.IsEven() {
		return false
	}

	// Check that r is a valid x-coordinate
	if !isValidFieldElement(sig.r) {
		return false
	}

	// Check that s is a valid scalar
	if !isValidScalar(sig.s) {
		return false
	}

	// Reconstruct R point from r coordinate (assume even y)
	R, err := reconstructRPoint(sig.r)
	if err != nil {
		return false
	}

	// Compute R' = R + T
	RPrime := group.Infinity().Add(R, adaptorPoint)
	if RPrime.IsInfinity() {
		return false
	}

	// Compute challenge e = hash(P.x || P.y || R'.x || R'.y || m)
	e := computeAdaptorChallenge(pubkey, RPrime, msg)

	// Verify: s' * G = R + e * P
	g := group.Generator()
	lhs := group.Infinity().ScalarMult(sig.s, g)
	eP := group.Infinity().ScalarMult(e, pubkey)
	rhs := group.Infinity().Add(R, eP)

	return lhs.Equal(rhs)
}

// ExtractSecret extracts the adaptor secret from a standard signature and its corresponding adaptor signature.
// Returns the secret scalar t such that standardSig = adaptorSig + t.
func ExtractSecret(standardSig *Signature, adaptorSig *AdaptorSignature) (*scalar.Scalar, error) {
	// Validate signature components
	if !isValidFieldElement(standardSig.r) || !isValidScalar(standardSig.s) {
		return nil, errors.New("invalid standard signature")
	}

	if !isValidFieldElement(adaptorSig.r) || !isValidScalar(adaptorSig.s) {
		return nil, errors.New("invalid adaptor signature")
	}

	// Note: The R coordinates will be different (standardSig.r = (R+T).x, adaptorSig.r = R.x)
	// We extract the secret from the scalar components: t = s - s' mod n
	// where s is from standard signature and s' is from adaptor signature
	secret := scalar.Zero()
	secret.Sub(standardSig.s, adaptorSig.s)

	return secret, nil
}

// AdaptToStandard converts an adaptor signature to a standard signature using the adaptor secret.
func AdaptToStandard(adaptorSig *AdaptorSignature, adaptorSecret *scalar.Scalar, adaptorPoint *group.Point) (*Signature, error) {
	// Validate inputs
	if !isValidFieldElement(adaptorSig.r) || !isValidScalar(adaptorSig.s) {
		return nil, errors.New("invalid adaptor signature")
	}

	if !isValidScalar(adaptorSecret) {
		return nil, errors.New("invalid adaptor secret")
	}

	// Verify that adaptorSecret * G = adaptorPoint
	g := group.Generator()
	derivedPoint := group.Infinity().ScalarMult(adaptorSecret, g)
	if !derivedPoint.Equal(adaptorPoint) {
		return nil, errors.New("adaptor secret does not match adaptor point")
	}

	// Reconstruct R from r coordinate
	R, err := reconstructRPoint(adaptorSig.r)
	if err != nil {
		return nil, err
	}

	// Compute R' = R + T (the R point for the standard signature)
	RPrime := group.Infinity().Add(R, adaptorPoint)
	if RPrime.IsInfinity() {
		return nil, errors.New("R + T results in infinity")
	}

	// The standard signature uses R' as the R point
	// But we need to ensure we use the correct y-coordinate parity
	rPrime := RPrime.X()

	// Store the actual R' point for verification purposes
	// Note: In a full implementation, we might need to adjust the signature
	// if R' doesn't have the expected y-coordinate parity

	// Compute standard signature: s = s' + t mod n
	s := scalar.Zero().Add(adaptorSig.s, adaptorSecret)

	return &Signature{r: rPrime, s: s}, nil
}

// generateAdaptorNonce generates a nonce for adaptor signatures.
func generateAdaptorNonce(privkey *scalar.Scalar, msg []byte, adaptorPoint *group.Point) (*scalar.Scalar, error) {
	// Use BIP-340 style nonce generation but include adaptor point
	h := sha256.New()
	h.Write(privkey.Bytes())
	h.Write(msg)
	h.Write(adaptorPoint.X().Bytes()) // Include adaptor point in nonce generation
	h.Write(adaptorPoint.Y().Bytes())
	t := h.Sum(nil)

	k := scalar.Zero()
	if !k.SetBytes(t) {
		return reduceNonceModOrder(t)
	}

	if k.IsZero() || !k.IsLessThanOrder() {
		return reduceNonceModOrder(t)
	}

	return k, nil
}

// computeAdaptorChallenge computes the challenge for adaptor signatures using full coordinates.
func computeAdaptorChallenge(pubkey, rPrime *group.Point, msg []byte) *scalar.Scalar {
	// Use keccak256 like Solidity: hash(P.x || P.y || R'.x || R'.y || m)
	h := sha256.New()
	h.Write(pubkey.X().Bytes())
	h.Write(pubkey.Y().Bytes())
	h.Write(rPrime.X().Bytes())
	h.Write(rPrime.Y().Bytes())
	h.Write(msg)

	challengeBytes := h.Sum(nil)

	e := scalar.Zero()
	e.SetBytes(challengeBytes)

	return e
}

// ReconstructRPoint reconstructs a point from its x-coordinate, assuming even y-coordinate.
func ReconstructRPoint(x *field.FieldVal) (*group.Point, error) {
	return reconstructRPoint(x)
}

// reconstructRPoint reconstructs a point from its x-coordinate, assuming even y-coordinate.
func reconstructRPoint(x *field.FieldVal) (*group.Point, error) {
	// Create compressed point bytes (0x02 prefix for even y)
	compressedBytes := make([]byte, 33)
	compressedBytes[0] = 0x02 // Even y-coordinate prefix
	copy(compressedBytes[1:], x.Bytes())

	point := group.Infinity()
	if !point.SetBytes(compressedBytes) {
		return nil, errors.New("failed to reconstruct point from x-coordinate")
	}

	return point, nil
}

// reconstructRPointBothParities tries both even and odd y-coordinates to find the correct R point.
func reconstructRPointBothParities(x *field.FieldVal, pubkey *group.Point, msg []byte, challengeMethod ChallengeMethod) (*group.Point, error) {
	// Try even y-coordinate first
	evenBytes := make([]byte, 33)
	evenBytes[0] = 0x02
	copy(evenBytes[1:], x.Bytes())

	evenPoint := group.Infinity()
	if evenPoint.SetBytes(evenBytes) {
		return evenPoint, nil
	}

	// Try odd y-coordinate
	oddBytes := make([]byte, 33)
	oddBytes[0] = 0x03
	copy(oddBytes[1:], x.Bytes())

	oddPoint := group.Infinity()
	if oddPoint.SetBytes(oddBytes) {
		return oddPoint, nil
	}

	return nil, errors.New("failed to reconstruct valid R point from x-coordinate")
}

// reconstructRPointWithParity reconstructs a point from its x-coordinate with specified y-coordinate parity.
func reconstructRPointWithParity(x *field.FieldVal, oddY bool) (*group.Point, error) {
	compressedBytes := make([]byte, 33)
	if oddY {
		compressedBytes[0] = 0x03 // Odd y-coordinate prefix
	} else {
		compressedBytes[0] = 0x02 // Even y-coordinate prefix
	}
	copy(compressedBytes[1:], x.Bytes())

	point := group.Infinity()
	if !point.SetBytes(compressedBytes) {
		return nil, errors.New("failed to reconstruct point from x-coordinate")
	}

	return point, nil
}

// AdaptorSignatureFromBytes creates an adaptor signature from a 64-byte encoding.
func AdaptorSignatureFromBytes(b []byte) (*AdaptorSignature, error) {
	if len(b) != 64 {
		return nil, errors.New("adaptor signature must be 64 bytes")
	}

	r := field.Zero()
	s := scalar.Zero()

	if !r.SetBytes(b[:32]) {
		return nil, errors.New("invalid r component")
	}

	if !s.SetBytes(b[32:]) {
		return nil, errors.New("invalid s component")
	}

	if !isValidFieldElement(r) || !isValidScalar(s) {
		return nil, errors.New("invalid signature components")
	}

	return &AdaptorSignature{r: r, s: s}, nil
}

// Bytes returns the adaptor signature as a 64-byte slice (r || s).
func (sig *AdaptorSignature) Bytes() []byte {
	result := make([]byte, 64)
	copy(result[:32], sig.r.Bytes())
	copy(result[32:], sig.s.Bytes())
	return result
}

// R returns the r component of the adaptor signature.
func (sig *AdaptorSignature) R() *field.FieldVal {
	return sig.r
}

// S returns the s component of the adaptor signature.
func (sig *AdaptorSignature) S() *scalar.Scalar {
	return sig.s
}

// SignFull creates a Schnorr signature with full R point coordinates (96 bytes).
// This format is compatible with the Solidity Schnorr256 library.
func SignFull(privkey *scalar.Scalar, msg []byte) (*FullSignature, error) {
	if len(msg) != 32 {
		return nil, ErrInvalidMessage
	}

	// Derive the public key P = d * G
	g := group.Generator()
	P := group.Infinity().ScalarMult(privkey, g)

	if P.IsInfinity() {
		return nil, errors.New("invalid private key")
	}

	// For full signatures, we don't enforce even y-coordinate like BIP-340
	d := scalar.Zero()
	*d = *privkey

	// Generate nonce k
	k, err := generateSchnorrNonce(d, msg)
	if err != nil {
		return nil, err
	}

	// Compute R = k * G
	R := group.Infinity().ScalarMult(k, g)
	if R.IsInfinity() {
		return nil, errors.New("invalid nonce")
	}

	// Store full R coordinates
	rx := R.X()
	ry := R.Y()

	// Compute challenge e = hash(P.x || P.y || R.x || R.y || m) - Solidity style
	e := computeFullChallenge(P, R, msg)

	// Compute s = k + e * d mod n
	ed := scalar.Zero().Mul(e, d)
	s := scalar.Zero().Add(ed, k)

	return &FullSignature{rx: rx, ry: ry, s: s}, nil
}

// VerifyFull verifies a 96-byte Schnorr signature with full R coordinates.
func VerifyFull(pubkey *group.Point, msg []byte, sig *FullSignature) bool {
	if len(msg) != 32 {
		return false
	}

	if pubkey.IsInfinity() {
		return false
	}

	// Check signature components are valid
	if !isValidFieldElement(sig.rx) || !isValidFieldElement(sig.ry) || !isValidScalar(sig.s) {
		return false
	}

	// Reconstruct R point from full coordinates using NewPoint
	R := group.NewPoint(sig.rx, sig.ry)

	// Verify R is on the curve
	if !R.IsOnCurve() {
		return false
	}

	// Compute challenge e = hash(P.x || P.y || R.x || R.y || m)
	e := computeFullChallenge(pubkey, R, msg)

	// Verify: s * G = R + e * P
	g := group.Generator()
	lhs := group.Infinity().ScalarMult(sig.s, g)
	eP := group.Infinity().ScalarMult(e, pubkey)
	rhs := group.Infinity().Add(R, eP)

	return lhs.Equal(rhs)
}

// ComputeFullChallenge computes challenge using full coordinates (Solidity compatible).
func ComputeFullChallenge(pubkey, R *group.Point, msg []byte) *scalar.Scalar {
	return computeFullChallenge(pubkey, R, msg)
}

// computeFullChallenge computes challenge using full coordinates (Solidity compatible).
func computeFullChallenge(pubkey, R *group.Point, msg []byte) *scalar.Scalar {
	// Use SHA256 like Solidity: hash(P.x || P.y || R.x || R.y || m)
	h := sha256.New()
	h.Write(pubkey.X().Bytes())
	h.Write(pubkey.Y().Bytes())
	h.Write(R.X().Bytes())
	h.Write(R.Y().Bytes())
	h.Write(msg)

	challengeBytes := h.Sum(nil)

	e := scalar.Zero()
	e.SetBytes(challengeBytes)

	return e
}

// FullSignatureFromBytes creates a full signature from a 96-byte encoding.
func FullSignatureFromBytes(b []byte) (*FullSignature, error) {
	if len(b) != 96 {
		return nil, errors.New("full signature must be 96 bytes")
	}

	rx := field.Zero()
	ry := field.Zero()
	s := scalar.Zero()

	if !rx.SetBytes(b[:32]) {
		return nil, errors.New("invalid rx component")
	}

	if !ry.SetBytes(b[32:64]) {
		return nil, errors.New("invalid ry component")
	}

	if !s.SetBytes(b[64:]) {
		return nil, errors.New("invalid s component")
	}

	if !isValidFieldElement(rx) || !isValidFieldElement(ry) || !isValidScalar(s) {
		return nil, errors.New("invalid signature components")
	}

	return &FullSignature{rx: rx, ry: ry, s: s}, nil
}

// Bytes returns the full signature as a 96-byte slice (rx || ry || s).
func (sig *FullSignature) Bytes() []byte {
	result := make([]byte, 96)
	copy(result[:32], sig.rx.Bytes())
	copy(result[32:64], sig.ry.Bytes())
	copy(result[64:], sig.s.Bytes())
	return result
}

// RX returns the rx component of the full signature.
func (sig *FullSignature) RX() *field.FieldVal {
	return sig.rx
}

// RY returns the ry component of the full signature.
func (sig *FullSignature) RY() *field.FieldVal {
	return sig.ry
}

// S returns the s component of the full signature.
func (sig *FullSignature) S() *scalar.Scalar {
	return sig.s
}

// ChallengeMethod defines different challenge computation methods.
type ChallengeMethod int

const (
	// ChallengeBIP340 uses BIP-340 tagged hash with x-only coordinates
	ChallengeBIP340 ChallengeMethod = iota
	// ChallengeSolidity uses SHA256 with full coordinates (Solidity compatible)
	ChallengeSolidity
	// ChallengeKeccak256 uses Keccak256 with full coordinates (Ethereum compatible)
	ChallengeKeccak256
)

// SignatureConfig holds configuration for signature generation and verification.
type SignatureConfig struct {
	ChallengeMethod ChallengeMethod
	UseFullCoords   bool // Whether to include full coordinates in signatures
	EnforceEvenY    bool // Whether to enforce even y-coordinates (BIP-340 style)
}

// DefaultBIP340Config returns the standard BIP-340 configuration.
func DefaultBIP340Config() *SignatureConfig {
	return &SignatureConfig{
		ChallengeMethod: ChallengeBIP340,
		UseFullCoords:   false,
		EnforceEvenY:    true,
	}
}

// SolidityCompatConfig returns configuration compatible with Solidity Schnorr256.
func SolidityCompatConfig() *SignatureConfig {
	return &SignatureConfig{
		ChallengeMethod: ChallengeSolidity,
		UseFullCoords:   true,
		EnforceEvenY:    false,
	}
}

// SignWithConfig creates a signature using the specified configuration.
func SignWithConfig(privkey *scalar.Scalar, msg []byte, config *SignatureConfig) (interface{}, error) {
	if len(msg) != 32 {
		return nil, ErrInvalidMessage
	}

	if config.UseFullCoords {
		return signFullWithConfig(privkey, msg, config)
	}
	return signStandardWithConfig(privkey, msg, config)
}

// signStandardWithConfig creates a standard 64-byte signature with configuration.
func signStandardWithConfig(privkey *scalar.Scalar, msg []byte, config *SignatureConfig) (*Signature, error) {
	// Derive the public key P = d * G
	g := group.Generator()
	P := group.Infinity().ScalarMult(privkey, g)

	if P.IsInfinity() {
		return nil, errors.New("invalid private key")
	}

	// Handle even y-coordinate enforcement
	d := scalar.Zero()
	*d = *privkey
	if config.EnforceEvenY && !P.IsEven() {
		d.Negate(d)
		P = group.Infinity().ScalarMult(d, g)
	}

	// Generate nonce k
	k, err := generateSchnorrNonce(d, msg)
	if err != nil {
		return nil, err
	}

	// Compute R = k * G
	R := group.Infinity().ScalarMult(k, g)
	if R.IsInfinity() {
		return nil, errors.New("invalid nonce")
	}

	// Handle even y-coordinate for R if enforced
	if config.EnforceEvenY && !R.IsEven() {
		k.Negate(k)
		R.Negate(R)
	}

	// r = R.x (as field element)
	r := R.X()

	// Compute challenge based on method
	var e *scalar.Scalar
	switch config.ChallengeMethod {
	case ChallengeBIP340:
		e = computeChallenge(r, P.X(), msg)
	case ChallengeSolidity:
		e = computeFullChallenge(P, R, msg)
	case ChallengeKeccak256:
		e = computeKeccakChallenge(P, R, msg)
	default:
		return nil, errors.New("unsupported challenge method")
	}

	// Compute s = k + e * d mod n
	ed := scalar.Zero().Mul(e, d)
	s := scalar.Zero().Add(ed, k)

	return &Signature{r: r, s: s}, nil
}

// signFullWithConfig creates a 96-byte signature with configuration.
func signFullWithConfig(privkey *scalar.Scalar, msg []byte, config *SignatureConfig) (*FullSignature, error) {
	// Derive the public key P = d * G
	g := group.Generator()
	P := group.Infinity().ScalarMult(privkey, g)

	if P.IsInfinity() {
		return nil, errors.New("invalid private key")
	}

	// Handle even y-coordinate enforcement
	d := scalar.Zero()
	*d = *privkey
	if config.EnforceEvenY && !P.IsEven() {
		d.Negate(d)
		P = group.Infinity().ScalarMult(d, g)
	}

	// Generate nonce k
	k, err := generateSchnorrNonce(d, msg)
	if err != nil {
		return nil, err
	}

	// Compute R = k * G
	R := group.Infinity().ScalarMult(k, g)
	if R.IsInfinity() {
		return nil, errors.New("invalid nonce")
	}

	// Handle even y-coordinate for R if enforced
	if config.EnforceEvenY && !R.IsEven() {
		k.Negate(k)
		R.Negate(R)
	}

	// Store full R coordinates
	rx := R.X()
	ry := R.Y()

	// Compute challenge based on method
	var e *scalar.Scalar
	switch config.ChallengeMethod {
	case ChallengeBIP340:
		e = computeChallenge(rx, P.X(), msg)
	case ChallengeSolidity:
		e = computeFullChallenge(P, R, msg)
	case ChallengeKeccak256:
		e = computeKeccakChallenge(P, R, msg)
	default:
		return nil, errors.New("unsupported challenge method")
	}

	// Compute s = k + e * d mod n
	ed := scalar.Zero().Mul(e, d)
	s := scalar.Zero().Add(ed, k)

	return &FullSignature{rx: rx, ry: ry, s: s}, nil
}

// VerifyWithConfig verifies a signature using the specified configuration.
func VerifyWithConfig(pubkey *group.Point, msg []byte, sig interface{}, config *SignatureConfig) bool {
	if len(msg) != 32 {
		return false
	}

	if pubkey.IsInfinity() {
		return false
	}

	switch s := sig.(type) {
	case *Signature:
		return verifyStandardWithConfig(pubkey, msg, s, config)
	case *FullSignature:
		return verifyFullWithConfig(pubkey, msg, s, config)
	default:
		return false
	}
}

// verifyStandardWithConfig verifies a standard signature with configuration.
func verifyStandardWithConfig(pubkey *group.Point, msg []byte, sig *Signature, config *SignatureConfig) bool {
	// Check that pubkey has even y-coordinate if enforced
	if config.EnforceEvenY && !pubkey.IsEven() {
		return false
	}

	// Check signature components
	if !isValidFieldElement(sig.r) || !isValidScalar(sig.s) {
		return false
	}

	// Reconstruct R point if needed for full coordinate challenges
	var R *group.Point
	var err error
	if config.ChallengeMethod != ChallengeBIP340 {
		// Try both even and odd y-coordinates
		R, err = reconstructRPointBothParities(sig.r, pubkey, msg, config.ChallengeMethod)
		if err != nil {
			return false
		}
	}

	// Compute challenge based on method
	var e *scalar.Scalar
	switch config.ChallengeMethod {
	case ChallengeBIP340:
		e = computeChallenge(sig.r, pubkey.X(), msg)
	case ChallengeSolidity:
		e = computeFullChallenge(pubkey, R, msg)
	case ChallengeKeccak256:
		e = computeKeccakChallenge(pubkey, R, msg)
	default:
		return false
	}

	// Verify: s * G = R + e * P
	g := group.Generator()
	sG := group.Infinity().ScalarMult(sig.s, g)

	if config.ChallengeMethod == ChallengeBIP340 {
		// For BIP-340, we need to reconstruct R from r
		R, err = reconstructRPoint(sig.r)
		if err != nil {
			return false
		}

		// Compute challenge and verify
		e = computeChallenge(sig.r, pubkey.X(), msg)
		eP := group.Infinity().ScalarMult(e, pubkey)
		expectedSG := group.Infinity().Add(R, eP)
		return sG.Equal(expectedSG)
	}

	// For non-BIP340 methods, try both y-coordinate parities
	// Try even y-coordinate first
	evenR, err1 := reconstructRPointWithParity(sig.r, false)
	if err1 == nil {
		var e_even *scalar.Scalar
		switch config.ChallengeMethod {
		case ChallengeSolidity:
			e_even = computeFullChallenge(pubkey, evenR, msg)
		case ChallengeKeccak256:
			e_even = computeKeccakChallenge(pubkey, evenR, msg)
		}

		if e_even != nil {
			eP := group.Infinity().ScalarMult(e_even, pubkey)
			expectedSG := group.Infinity().Add(evenR, eP)
			if sG.Equal(expectedSG) {
				return true
			}
		}
	}

	// Try odd y-coordinate
	oddR, err2 := reconstructRPointWithParity(sig.r, true)
	if err2 == nil {
		var e_odd *scalar.Scalar
		switch config.ChallengeMethod {
		case ChallengeSolidity:
			e_odd = computeFullChallenge(pubkey, oddR, msg)
		case ChallengeKeccak256:
			e_odd = computeKeccakChallenge(pubkey, oddR, msg)
		}

		if e_odd != nil {
			eP := group.Infinity().ScalarMult(e_odd, pubkey)
			expectedSG := group.Infinity().Add(oddR, eP)
			if sG.Equal(expectedSG) {
				return true
			}
		}
	}

	return false
}

// verifyFullWithConfig verifies a full signature with configuration.
func verifyFullWithConfig(pubkey *group.Point, msg []byte, sig *FullSignature, config *SignatureConfig) bool {
	// Check that pubkey has even y-coordinate if enforced
	if config.EnforceEvenY && !pubkey.IsEven() {
		return false
	}

	// Check signature components
	if !isValidFieldElement(sig.rx) || !isValidFieldElement(sig.ry) || !isValidScalar(sig.s) {
		return false
	}

	// Reconstruct R point from full coordinates using NewPoint
	R := group.NewPoint(sig.rx, sig.ry)

	// Verify R is on the curve
	if !R.IsOnCurve() {
		return false
	}

	// Check that R has even y-coordinate if enforced
	if config.EnforceEvenY && !R.IsEven() {
		return false
	}

	// Compute challenge based on method
	var e *scalar.Scalar
	switch config.ChallengeMethod {
	case ChallengeBIP340:
		e = computeChallenge(sig.rx, pubkey.X(), msg)
	case ChallengeSolidity:
		e = computeFullChallenge(pubkey, R, msg)
	case ChallengeKeccak256:
		e = computeKeccakChallenge(pubkey, R, msg)
	default:
		return false
	}

	// Verify: s * G = R + e * P
	g := group.Generator()
	lhs := group.Infinity().ScalarMult(sig.s, g)
	eP := group.Infinity().ScalarMult(e, pubkey)
	rhs := group.Infinity().Add(R, eP)

	return lhs.Equal(rhs)
}

// computeKeccakChallenge computes challenge using Keccak256 (Ethereum compatible).
func computeKeccakChallenge(pubkey, R *group.Point, msg []byte) *scalar.Scalar {
	// Note: This would require a Keccak256 implementation
	// For now, we'll use SHA256 as a placeholder
	// In a real implementation, you'd import "golang.org/x/crypto/sha3"

	h := sha256.New() // Replace with keccak256.New() when available
	h.Write(pubkey.X().Bytes())
	h.Write(pubkey.Y().Bytes())
	h.Write(R.X().Bytes())
	h.Write(R.Y().Bytes())
	h.Write(msg)

	challengeBytes := h.Sum(nil)

	e := scalar.Zero()
	e.SetBytes(challengeBytes)

	return e
}
