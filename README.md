# Pure Go Secp256k1 Library

This package provides a 100% Go implementation of the secp256k1 elliptic curve, including support for ECDSA and BIP-340 Schnorr signatures. The library is designed to be a pure Go alternative to C-based libraries, offering a high-level API that is easy to use and secure by default.

## Features

- **Pure Go**: No CGO or external dependencies required.
- **ECDSA**: Signing and verification of ECDSA signatures.
- **Schnorr**: BIP-340 compliant Schnorr signing and verification.
- **Constant-Time Operations**: Secret key operations are implemented in constant time to prevent timing side-channel attacks.
- **Modular Design**: The library is organized into sub-packages for different cryptographic primitives, allowing for a smaller dependency footprint.

## Installation

To install the library, use `go get`:

```bash
go get github.com/rafaelescrich/go-secp256k1
```

## Usage

### Key Generation

```go
import "github.com/rafaelescrich/go-secp256k1"

// Generate a new private key
priv, err := secp256k1.GeneratePrivateKey()
if err != nil {
    // Handle error
}

// Derive the public key
pub := priv.PublicKey()
```

### ECDSA Signing and Verification

```go
import (
    "crypto/sha256"
    "github.com/rafaelescrich/go-secp256k1"
)

// Create a message hash
msg := []byte("Hello, ECDSA!")
msgHash := sha256.Sum256(msg)

// Sign the message
sig, err := priv.SignECDSA(msgHash[:])
if err != nil {
    // Handle error
}

// Verify the signature
valid := pub.VerifyECDSA(sig, msgHash[:])
if !valid {
    // Signature is invalid
}
```

### Schnorr Signing and Verification (BIP-340)

```go
import (
    "crypto/sha256"
    "github.com/rafaelescrich/go-secp256k1"
)

// Create a message hash (must be 32 bytes for Schnorr)
msg := sha256.Sum256([]byte("Hello, Schnorr!"))

// Sign the message
sig, err := priv.SignSchnorr(msg[:])
if err != nil {
    // Handle error
}

// Verify the signature
valid := pub.VerifySchnorr(sig, msg[:])
if !valid {
    // Signature is invalid
}
```

## Security

This library is designed with security as a top priority. All operations involving secret keys are implemented in constant time to mitigate timing-based side-channel attacks. However, as with any cryptographic library, it is important to use it correctly and to be aware of the potential security implications.

## Performance

The library provides comprehensive benchmarks for all cryptographic operations. Run benchmarks to see current performance metrics:

```bash
# Run all benchmarks
go test -bench=. -benchmem ./...

# Run specific package benchmarks
go test -bench=. -benchmem ./field
go test -bench=. -benchmem ./scalar
go test -bench=. -benchmem ./schnorr
```

### Latest Benchmarks (macOS ARM64, Apple M3 Pro)

**Main Operations:**
| Operation | Performance | Memory | Allocations |
|-----------|-------------|--------|-------------|
| Key Generation | 282.0 ns/op | 136 B/op | 4 allocs/op |
| Public Key Derivation | 1,053,215 ns/op | 833,623 B/op | 16,049 allocs/op |
| ECDSA Sign | 1,039,500 ns/op | 828,076 B/op | 15,940 allocs/op |
| ECDSA Verify | 1,111,483 ns/op | 816,399 B/op | 15,710 allocs/op |
| Schnorr Sign | 3,063,565 ns/op | 2,438,605 B/op | 46,915 allocs/op |
| Schnorr Verify | 2,084,044 ns/op | 1,658,565 B/op | 31,928 allocs/op |

**Field Operations:**
| Operation | Performance | Memory | Allocations |
|-----------|-------------|--------|-------------|
| Field Add | 183.4 ns/op | 328 B/op | 9 allocs/op |
| Field Mul | 186.3 ns/op | 328 B/op | 9 allocs/op |
| Field Square | 191.3 ns/op | 328 B/op | 9 allocs/op |
| Field Inverse | 257.2 ns/op | 496 B/op | 15 allocs/op |

**Scalar Operations:**
| Operation | Performance | Memory | Allocations |
|-----------|-------------|--------|-------------|
| Scalar Add | 189.1 ns/op | 328 B/op | 9 allocs/op |
| Scalar Mul | 197.1 ns/op | 328 B/op | 9 allocs/op |
| Scalar Square | 187.6 ns/op | 328 B/op | 9 allocs/op |
| Scalar Inverse | 258.1 ns/op | 496 B/op | 15 allocs/op |

The library provides competitive performance for a pure Go implementation, with field and scalar operations in the ~200ns range and full cryptographic operations in the 1-3ms range.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or to open an issue if you find a bug or have a feature request.

## License

This library is licensed under the MIT License. See the LICENSE.md file for more information.
