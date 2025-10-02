// Package ecdh implements ECDH (Elliptic Curve Diffie-Hellman) for secp256k1.
package ecdh

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/rafaelescrich/go-secp256k1/group"
	"github.com/rafaelescrich/go-secp256k1/scalar"
)

// Common errors
var (
	ErrInvalidPrivateKey = errors.New("invalid private key")
	ErrInvalidPublicKey  = errors.New("invalid public key")
	ErrInvalidPoint      = errors.New("invalid point")
)

var (
	secp256k1P = new(big.Int).SetBytes([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
	})
	secp256k1B = big.NewInt(7)
	two        = big.NewInt(2)
	three      = big.NewInt(3)
)

type affinePoint struct {
	x, y     *big.Int
	infinity bool
}

func newAffinePoint(p *group.Point) (*affinePoint, error) {
	if p == nil {
		return nil, ErrInvalidPublicKey
	}
	if p.IsInfinity() {
		return &affinePoint{infinity: true}, nil
	}
	if !p.IsOnCurve() {
		return nil, ErrInvalidPublicKey
	}

	return &affinePoint{
		x: new(big.Int).SetBytes(p.X().Bytes()),
		y: new(big.Int).SetBytes(p.Y().Bytes()),
	}, nil
}

func scalarToBigInt(s *scalar.Scalar) *big.Int {
	if s == nil {
		return big.NewInt(0)
	}
	return new(big.Int).SetBytes(s.Bytes())
}

func padTo32(b []byte) []byte {
	if len(b) > 32 {
		b = b[len(b)-32:]
	}
	if len(b) == 32 {
		return b
	}
	res := make([]byte, 32)
	copy(res[32-len(b):], b)
	return res
}

func modAdd(a, b *big.Int) *big.Int {
	sum := new(big.Int).Add(a, b)
	sum.Mod(sum, secp256k1P)
	return sum
}

func modSub(a, b *big.Int) *big.Int {
	diff := new(big.Int).Sub(a, b)
	diff.Mod(diff, secp256k1P)
	if diff.Sign() < 0 {
		diff.Add(diff, secp256k1P)
	}
	return diff
}

func modMul(a, b *big.Int) *big.Int {
	prod := new(big.Int).Mul(a, b)
	prod.Mod(prod, secp256k1P)
	return prod
}

func modInv(a *big.Int) *big.Int {
	inv := new(big.Int).ModInverse(a, secp256k1P)
	if inv == nil {
		return big.NewInt(0)
	}
	return inv
}

func affineAdd(a, b *affinePoint) *affinePoint {
	if a.infinity {
		return b.copy()
	}
	if b.infinity {
		return a.copy()
	}

	if a.x.Cmp(b.x) == 0 {
		sumY := modAdd(a.y, b.y)
		if sumY.Sign() == 0 {
			return &affinePoint{infinity: true}
		}
		return affineDouble(a)
	}

	numerator := modSub(b.y, a.y)
	denominator := modSub(b.x, a.x)
	inv := modInv(denominator)
	if inv.Sign() == 0 {
		return &affinePoint{infinity: true}
	}
	lambda := modMul(numerator, inv)
	lambdaSq := modMul(lambda, lambda)
	xr := modSub(modSub(lambdaSq, a.x), b.x)
	yr := modSub(modMul(lambda, modSub(a.x, xr)), a.y)
	return &affinePoint{x: xr, y: yr}
}

func affineDouble(p *affinePoint) *affinePoint {
	if p.infinity || p.y.Sign() == 0 {
		return &affinePoint{infinity: true}
	}

	xSq := modMul(p.x, p.x)
	threeXSq := modMul(three, xSq)
	twoY := modMul(two, p.y)
	inv := modInv(twoY)
	if inv.Sign() == 0 {
		return &affinePoint{infinity: true}
	}
	lambda := modMul(threeXSq, inv)
	lambdaSq := modMul(lambda, lambda)
	twoX := modMul(two, p.x)
	xr := modSub(lambdaSq, twoX)
	yr := modSub(modMul(lambda, modSub(p.x, xr)), p.y)
	return &affinePoint{x: xr, y: yr}
}

func (p *affinePoint) copy() *affinePoint {
	if p == nil {
		return nil
	}
	if p.infinity {
		return &affinePoint{infinity: true}
	}
	return &affinePoint{x: new(big.Int).Set(p.x), y: new(big.Int).Set(p.y)}
}

func scalarMultiply(p *affinePoint, k *big.Int) *affinePoint {
	if k.Sign() == 0 || p.infinity {
		return &affinePoint{infinity: true}
	}

	result := &affinePoint{infinity: true}
	addend := p.copy()

	for i := k.BitLen() - 1; i >= 0; i-- {
		result = affineDouble(result)
		if k.Bit(i) == 1 {
			result = affineAdd(result, addend)
		}
	}

	return result
}

// ComputeSharedSecret computes the shared secret using ECDH.
// Given a private key and a peer's public key, it returns the shared secret.
func ComputeSharedSecret(privkey *scalar.Scalar, peerPubkey *group.Point) ([]byte, error) {
	if privkey.IsZero() {
		return nil, ErrInvalidPrivateKey
	}

	peerAffine, err := newAffinePoint(peerPubkey)
	if err != nil || peerAffine.infinity {
		return nil, ErrInvalidPublicKey
	}

	shared := scalarMultiply(peerAffine, scalarToBigInt(privkey))
	if shared.infinity {
		return nil, ErrInvalidPoint
	}

	sharedX := padTo32(shared.x.Bytes())
	hash := sha256.Sum256(sharedX)
	return hash[:], nil
}

// GenerateSharedSecret generates a shared secret between two parties.
// This is a convenience function that combines the ECDH computation.
func GenerateSharedSecret(privkey *scalar.Scalar, peerPubkeyBytes []byte) ([]byte, error) {
	if len(peerPubkeyBytes) != 33 {
		return nil, ErrInvalidPublicKey
	}

	// Parse the peer's public key
	peerPubkey := group.Infinity()
	if !peerPubkey.SetBytes(peerPubkeyBytes) {
		return nil, ErrInvalidPublicKey
	}

	return ComputeSharedSecret(privkey, peerPubkey)
}

// ValidatePublicKey validates that a public key is valid for ECDH.
func ValidatePublicKey(pubkey *group.Point) bool {
	if pubkey.IsInfinity() {
		return false
	}

	// Check that the point is on the curve
	if !pubkey.IsOnCurve() {
		return false
	}

	// Check that the point is not the point at infinity
	if pubkey.X().IsZero() && pubkey.Y().IsZero() {
		return false
	}

	return true
}

// ValidatePrivateKey validates that a private key is valid for ECDH.
func ValidatePrivateKey(privkey *scalar.Scalar) bool {
	if privkey.IsZero() {
		return false
	}

	// Check that the private key is less than the curve order
	curveOrder := scalar.Zero()
	curveOrder.SetBytes([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
	})

	// Check that the private key is less than the curve order
	return privkey.IsLessThanOrder()
}
