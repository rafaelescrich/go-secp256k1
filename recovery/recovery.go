package recovery

import (
	"crypto/ecdsa"
	"errors"

	"github.com/rafaelescrich/go-secp256k1"
	"github.com/rafaelescrich/go-secp256k1/group"
	"github.com/rafaelescrich/go-secp256k1/scalar"
)

// RecoverPubkey recovers the public key from a signature and message hash.
// sig should be 65 bytes: [R || S || V] where V is recovery id (0-3 or 27-31)
func RecoverPubkey(msgHash, sig []byte) ([]byte, error) {
	if len(msgHash) != 32 {
		return nil, errors.New("invalid message hash length")
	}
	if len(sig) != 65 {
		return nil, errors.New("invalid signature length")
	}

	// Extract recovery ID (normalize 27-31 to 0-3)
	v := sig[64]
	if v >= 27 {
		v -= 27
	}
	if v > 3 {
		return nil, errors.New("invalid recovery id")
	}

	// Parse r and s
	r := scalar.Zero()
	s := scalar.Zero()
	if !r.SetBytes(sig[:32]) || r.IsZero() {
		return nil, errors.New("invalid r value")
	}
	if !s.SetBytes(sig[32:64]) || s.IsZero() {
		return nil, errors.New("invalid s value")
	}

	// Recover the public key point
	pubPoint, err := recoverPoint(r, s, msgHash, v)
	if err != nil {
		return nil, err
	}

	// Return uncompressed format: 64 bytes (X || Y)
	return pubPoint.BytesUncompressed(), nil
}

// SigToECDSA recovers the ECDSA public key from a signature.
func SigToECDSA(msgHash, sig []byte) (*ecdsa.PublicKey, error) {
	pubBytes, err := RecoverPubkey(msgHash, sig)
	if err != nil {
		return nil, err
	}

	// pubBytes is 64 bytes (X || Y)
	if len(pubBytes) != 64 {
		return nil, errors.New("invalid recovered public key")
	}

	pub, err := secp256k1.PublicKeyFromUncompressed(pubBytes)
	if err != nil {
		return nil, err
	}

	return pub.ToECDSA(), nil
}

func recoverPoint(r, s *scalar.Scalar, msgHash []byte, recID byte) (*group.Point, error) {
	// e = hash(m)
	e := scalar.Zero()
	if !e.SetBytes(msgHash) {
		return nil, errors.New("invalid message hash")
	}

	// For recovery id bit 1, add order to x-coordinate
	rBytes := r.Bytes()
	if recID >= 2 {
		// This case is for x-coordinates that wrapped around
		return nil, errors.New("overflow recovery not implemented")
	}

	// Construct R from r (x-coordinate) and recID bit 0 (y parity)
	R := group.Infinity()
	if !R.SetCompressed(rBytes, recID&1 == 1) {
		return nil, errors.New("failed to construct R point")
	}

	// Compute: Q = r^(-1) * (s*R - e*G)
	rInv := scalar.Zero().Inverse(r)
	eG := group.Infinity().ScalarMult(e, group.Generator())
	sR := group.Infinity().ScalarMult(s, R)

	// sR - eG = sR + (-eG)
	diff := group.Infinity().Sub(sR, eG)

	// Q = rInv * diff
	Q := group.Infinity().ScalarMult(rInv, diff)

	if Q.IsInfinity() {
		return nil, errors.New("recovered point is infinity")
	}

	return Q, nil
}
