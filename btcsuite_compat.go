// Package secp256k1 compatibility layer for btcsuite/btcd
package secp256k1

import (
	"crypto/elliptic"
	"math/big"
)

// Compatibility types and functions for btcsuite/btcd/btcec/v2

// ModNScalar represents a scalar modulo the curve order
type ModNScalar struct {
	*big.Int
}

// SetByteSlice sets the ModNScalar from a byte slice
func (s *ModNScalar) SetByteSlice(b []byte) bool {
	if s.Int == nil {
		s.Int = new(big.Int)
	}
	s.SetBytes(b)
	// Check if it overflows the curve order (simplified check)
	return s.Cmp(S256().Params().N) >= 0
}

// FieldVal represents a field element (placeholder implementation)
type FieldVal struct {
	value *big.Int
}

// JacobianPoint represents a point in Jacobian coordinates (placeholder implementation)
type JacobianPoint struct {
	x, y, z *big.Int
}

// Error represents a secp256k1 error
type Error struct {
	Kind ErrorKind
	Desc string
}

func (e Error) Error() string {
	return e.Desc
}

// ErrorKind represents the kind of error
type ErrorKind int

const (
	// ErrInvalidPrivKey indicates an invalid private key
	ErrInvalidPrivKey ErrorKind = iota
	// ErrInvalidPubKey indicates an invalid public key
	ErrInvalidPubKey
)

// CurveParams is an alias for elliptic.CurveParams
type CurveParams elliptic.CurveParams

// Params returns the secp256k1 curve parameters
func Params() *elliptic.CurveParams {
	return S256().Params()
}

// GenerateSharedSecret generates a shared secret using ECDH
func GenerateSharedSecret(privKey []byte, pubKey []byte) []byte {
	// This is a placeholder implementation
	// You should implement proper ECDH based on your existing code
	return make([]byte, 32)
}

// Additional compatibility functions that btcsuite might expect

// NewModNScalar creates a new ModNScalar
func NewModNScalar() *ModNScalar {
	return &ModNScalar{Int: new(big.Int)}
}

// NewFieldVal creates a new FieldVal
func NewFieldVal() *FieldVal {
	return &FieldVal{value: new(big.Int)}
}

// NewJacobianPoint creates a new JacobianPoint
func NewJacobianPoint() *JacobianPoint {
	return &JacobianPoint{x: new(big.Int), y: new(big.Int), z: new(big.Int)}
}
