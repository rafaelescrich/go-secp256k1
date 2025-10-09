package secp256k1

import (
	"github.com/rafaelescrich/go-secp256k1/field"
	"github.com/rafaelescrich/go-secp256k1/group"
	"github.com/rafaelescrich/go-secp256k1/scalar"
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

	// For BIP-340, ensure the public key has an even y-coordinate
	pubPoint := pub.point
	if !pubPoint.IsEven() {
		// Negate the point to get even y-coordinate
		pubPoint = group.Infinity().Negate(pubPoint)
	}

	return schnorr.Verify(pubPoint, msg, schnorrSig)
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

// AdaptorSchnorrSignature represents a Schnorr adaptor signature.
type AdaptorSchnorrSignature struct {
	r *field.FieldVal
	s *scalar.Scalar
}

// FullSchnorrSignature represents a 96-byte Schnorr signature with full coordinates.
type FullSchnorrSignature struct {
	rx *field.FieldVal
	ry *field.FieldVal
	s  *scalar.Scalar
}

// SignSchnorrAdaptor creates a Schnorr adaptor signature for the given message and adaptor point.
func (priv *PrivateKey) SignSchnorrAdaptor(msg []byte, adaptorPoint *PublicKey) (*AdaptorSchnorrSignature, error) {
	sig, err := schnorr.AdaptorSign(priv.key, msg, adaptorPoint.point)
	if err != nil {
		return nil, err
	}

	return &AdaptorSchnorrSignature{
		r: sig.R(),
		s: sig.S(),
	}, nil
}

// VerifySchnorrAdaptor verifies a Schnorr adaptor signature against the given message and adaptor point.
func (pub *PublicKey) VerifySchnorrAdaptor(sig *AdaptorSchnorrSignature, msg []byte, adaptorPoint *PublicKey) bool {
	adaptorSig, err := schnorr.AdaptorSignatureFromBytes(sig.Bytes())
	if err != nil {
		return false
	}

	return schnorr.AdaptorVerify(pub.point, msg, adaptorSig, adaptorPoint.point)
}

// SignSchnorrFull creates a 96-byte Schnorr signature with full R coordinates.
func (priv *PrivateKey) SignSchnorrFull(msg []byte) (*FullSchnorrSignature, error) {
	sig, err := schnorr.SignFull(priv.key, msg)
	if err != nil {
		return nil, err
	}

	return &FullSchnorrSignature{
		rx: sig.RX(),
		ry: sig.RY(),
		s:  sig.S(),
	}, nil
}

// VerifySchnorrFull verifies a 96-byte Schnorr signature with full R coordinates.
func (pub *PublicKey) VerifySchnorrFull(sig *FullSchnorrSignature, msg []byte) bool {
	fullSig, err := schnorr.FullSignatureFromBytes(sig.Bytes())
	if err != nil {
		return false
	}

	return schnorr.VerifyFull(pub.point, msg, fullSig)
}

// SignSchnorrWithConfig creates a Schnorr signature using the specified configuration.
func (priv *PrivateKey) SignSchnorrWithConfig(msg []byte, config *schnorr.SignatureConfig) (interface{}, error) {
	return schnorr.SignWithConfig(priv.key, msg, config)
}

// VerifySchnorrWithConfig verifies a Schnorr signature using the specified configuration.
func (pub *PublicKey) VerifySchnorrWithConfig(sig interface{}, msg []byte, config *schnorr.SignatureConfig) bool {
	return schnorr.VerifyWithConfig(pub.point, msg, sig, config)
}

// ExtractSchnorrSecret extracts the adaptor secret from a standard and adaptor signature pair.
func ExtractSchnorrSecret(standardSig *SchnorrSignature, adaptorSig *AdaptorSchnorrSignature) (*scalar.Scalar, error) {
	stdSig, err := schnorr.SignatureFromBytes(standardSig.Bytes())
	if err != nil {
		return nil, err
	}

	adaptSig, err := schnorr.AdaptorSignatureFromBytes(adaptorSig.Bytes())
	if err != nil {
		return nil, err
	}

	return schnorr.ExtractSecret(stdSig, adaptSig)
}

// AdaptSchnorrToStandard converts an adaptor signature to a standard signature using the adaptor secret.
func AdaptSchnorrToStandard(adaptorSig *AdaptorSchnorrSignature, adaptorSecret *scalar.Scalar, adaptorPoint *PublicKey) (*SchnorrSignature, error) {
	adaptSig, err := schnorr.AdaptorSignatureFromBytes(adaptorSig.Bytes())
	if err != nil {
		return nil, err
	}

	stdSig, err := schnorr.AdaptToStandard(adaptSig, adaptorSecret, adaptorPoint.point)
	if err != nil {
		return nil, err
	}

	return &SchnorrSignature{
		r: stdSig.R(),
		s: stdSig.S(),
	}, nil
}

// Bytes returns the adaptor signature as a 64-byte slice (r || s).
func (sig *AdaptorSchnorrSignature) Bytes() []byte {
	result := make([]byte, 64)
	copy(result[:32], sig.r.Bytes())
	copy(result[32:], sig.s.Bytes())
	return result
}

// Bytes returns the full signature as a 96-byte slice (rx || ry || s).
func (sig *FullSchnorrSignature) Bytes() []byte {
	result := make([]byte, 96)
	copy(result[:32], sig.rx.Bytes())
	copy(result[32:64], sig.ry.Bytes())
	copy(result[64:], sig.s.Bytes())
	return result
}

// AdaptorSchnorrSignatureFromBytes creates an adaptor signature from a 64-byte encoding.
func AdaptorSchnorrSignatureFromBytes(b []byte) (*AdaptorSchnorrSignature, error) {
	sig, err := schnorr.AdaptorSignatureFromBytes(b)
	if err != nil {
		return nil, err
	}

	return &AdaptorSchnorrSignature{
		r: sig.R(),
		s: sig.S(),
	}, nil
}

// FullSchnorrSignatureFromBytes creates a full signature from a 96-byte encoding.
func FullSchnorrSignatureFromBytes(b []byte) (*FullSchnorrSignature, error) {
	sig, err := schnorr.FullSignatureFromBytes(b)
	if err != nil {
		return nil, err
	}

	return &FullSchnorrSignature{
		rx: sig.RX(),
		ry: sig.RY(),
		s:  sig.S(),
	}, nil
}
