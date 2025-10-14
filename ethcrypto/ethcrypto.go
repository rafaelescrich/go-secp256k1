package ethcrypto

import (
	"crypto/ecdsa"
	"errors"

	"github.com/rafaelescrich/go-secp256k1/recovery"
)

// RecoverPubkey returns the uncompressed public key bytes (65 bytes, 0x04 || X || Y)
// to match geth's crypto.RecoverPubkey behavior.
func RecoverPubkey(msgHash, sig []byte) ([]byte, error) {
	pk, err := recovery.RecoverPubkey(msgHash, sig)
	if err != nil {
		return nil, err
	}
	// RecoverPubkey returns 64-bytes (X||Y), prepend 0x04
	if len(pk) == 64 {
		out := make([]byte, 65)
		out[0] = 0x04
		copy(out[1:], pk)
		return out, nil
	}
	if len(pk) == 65 {
		return pk, nil
	}
	return nil, errors.New("secp256k1: unexpected pubkey length")
}

// SigToPub recovers the ECDSA public key from a signature.
func SigToPub(msgHash, sig []byte) (*ecdsa.PublicKey, error) {
	return recovery.SigToECDSA(msgHash, sig)
}
