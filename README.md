# ZHTP Crypto - Post-Quantum Cryptography Foundation

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Real implementations of quantum-resistant cryptographic primitives for the ZHTP (Zero-Hash Transport Protocol) ecosystem.

## 🛡️ Post-Quantum Security

This package implements **production-ready** post-quantum cryptography:

- **CRYSTALS-Dilithium** for digital signatures (NIST standardized)
- **CRYSTALS-Kyber** for key encapsulation (NIST standardized)
- **ChaCha20-Poly1305** for symmetric encryption
- **BLAKE3 & SHA-3** for cryptographic hashing
- **Ed25519** for classical compatibility
- **Ring signatures** for anonymity
- **Multi-signatures** for shared control

## 🔐 Zero-Knowledge Integration

Provides trait interfaces for zero-knowledge proofs implemented by the `lib-proofs` package:

- Identity proofs without revealing personal information
- Range proofs without revealing values
- Storage access proofs without revealing data
- Merkle inclusion proofs
- Transaction privacy proofs

## 🚀 Features

- ✅ **Real CRYSTALS implementations** (not simplified versions)
- ✅ **Memory security** with zeroization
- ✅ **Browser compatibility** with development signatures
- ✅ **Modular architecture** with clean separation
- ✅ **Comprehensive testing** of all cryptographic operations
- ✅ **ZK trait interfaces** for external proof systems
- ✅ **Production-ready** performance optimizations

## 📦 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
lib-crypto = { path = "../lib-crypto" }

# For zero-knowledge functionality:
lib-proofs = { path = "../lib-proofs" }
```

## 🔧 Usage

### Basic Cryptographic Operations

```rust
use lib_crypto::{KeyPair, hash_blake3};

// Generate post-quantum keypair
let keypair = KeyPair::generate()?;

// Sign and verify messages
let message = b"Hello ZHTP!";
let signature = keypair.sign(message)?;
assert!(keypair.verify(&signature, message)?);

// Hybrid encryption (post-quantum + symmetric)
let plaintext = b"Secret data";
let ciphertext = keypair.encrypt(plaintext, b"associated_data")?;
let decrypted = keypair.decrypt(&ciphertext, b"associated_data")?;
assert_eq!(plaintext, &decrypted[..]);

// Cryptographic hashing
let hash = hash_blake3(b"data to hash");
```

### Zero-Knowledge Proofs

```rust
use lib_crypto::KeyPair;
// For actual ZK functionality, use lib-proofs:
// use lib_proofs::plonky2::ZkProofSystem;

let keypair = KeyPair::generate()?;

// ZK trait interface (requires lib-proofs for implementation)
let zk_result = keypair.prove_identity(25, 840, 9999, 18, 840);
// Returns helpful error message pointing to lib-proofs package
```

## 🏗️ Architecture

```
lib-crypto/
├── src/
│   ├── types/           # Core type definitions
│   ├── keypair/         # KeyPair generation and operations
│   ├── post_quantum/    # CRYSTALS-Dilithium & Kyber
│   ├── classical/       # Ed25519 & Curve25519
│   ├── symmetric/       # ChaCha20-Poly1305 encryption
│   ├── hashing/         # BLAKE3 & SHA-3
│   ├── random/          # Secure random generation
│   ├── advanced/        # Ring & multi-signatures
│   ├── kdf/             # Key derivation functions
│   ├── verification/    # Signature verification
│   ├── zk_integration/  # ZK proof trait interfaces
│   └── utils/           # Utility functions
├── benches/             # Performance benchmarks
└── tests/               # Integration tests
```

## 🔗 Integration with ZK

The `lib-crypto` package provides trait interfaces for zero-knowledge functionality:

- **Trait-based design** avoids circular dependencies
- **Clear error messages** guide users to `lib-proofs` package
- **Seamless integration** when both packages are used together
- **Production flexibility** for different ZK implementations

See [INTEGRATION_GUIDE.md](./INTEGRATION_GUIDE.md) for detailed usage patterns.

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run benchmarks
cargo bench
```

## 📊 Performance

- **CRYSTALS-Dilithium**: ~1ms signing, ~0.5ms verification
- **CRYSTALS-Kyber**: ~0.3ms encapsulation, ~0.2ms decapsulation
- **ChaCha20-Poly1305**: ~500MB/s encryption throughput
- **BLAKE3**: ~1GB/s hashing throughput

## 🛠️ Dependencies

### Core Cryptography
- `pqcrypto-dilithium` - CRYSTALS-Dilithium signatures
- `pqcrypto-kyber` - CRYSTALS-Kyber key encapsulation
- `ed25519-dalek` - Ed25519 signatures
- `chacha20poly1305` - Symmetric encryption
- `blake3` - Fast cryptographic hashing

### Security
- `zeroize` - Secure memory management
- `rand` - Cryptographically secure randomness

### ZK Integration
- Uses trait interfaces implemented by external packages
- No direct ZK dependencies to avoid circular references

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please ensure all cryptographic changes are thoroughly tested and reviewed.

## ⚠️ Security Notice

This implementation uses standardized post-quantum cryptographic algorithms. However, always conduct security audits before production use.

## 🔮 Quantum Resistance

This package implements algorithms selected by NIST for post-quantum standardization:

- **CRYSTALS-Dilithium** (digital signatures)
- **CRYSTALS-Kyber** (key encapsulation)

These algorithms are designed to be secure against both classical and quantum computer attacks.
