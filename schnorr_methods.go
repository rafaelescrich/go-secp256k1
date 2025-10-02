package secp256k1

import (
	"github.com/rafaelescrich/go-secp256k1/schnorr"
)

// SignSchnorr creates a BIP-340 Schnorr signature for the given 32-byte message.
func (priv *PrivateKey) SignSchnorr(msg []byte) (*SchnorrSignature, error) {
	sig, err := schnorr.Sign(priv.key, msg)
	if err != nil {
		return nil, err
	}

	return &SchnorrSignature{
		r: sig.R(),
		s: sig.S(),
	}, nil
}

// VerifySchnorr verifies a BIP-340 Schnorr signature against the given message.
func (pub *PublicKey) VerifySchnorr(sig *SchnorrSignature, msg []byte) bool {
	schnorrSig, err := schnorr.SignatureFromBytes(sig.Bytes())
	if err != nil {
		return false
	}

	return schnorr.Verify(pub.point, msg, schnorrSig)
}

// SchnorrSignatureFromBytes creates a Schnorr signature from a 64-byte encoding.
func SchnorrSignatureFromBytes(b []byte) (*SchnorrSignature, error) {
	sig, err := schnorr.SignatureFromBytes(b)
	if err != nil {
		return nil, err
	}

	return &SchnorrSignature{
		r: sig.R(),
		s: sig.S(),
	}, nil
}

// Bytes returns the Schnorr signature as a 64-byte slice (r || s).
func (sig *SchnorrSignature) Bytes() []byte {
	result := make([]byte, 64)
	copy(result[:32], sig.r.Bytes())
	copy(result[32:], sig.s.Bytes())
	return result
}
