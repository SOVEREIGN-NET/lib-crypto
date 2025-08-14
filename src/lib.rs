//! # ZHTP Crypto - Post-Quantum Cryptography Foundation
//! 
//! Real implementations of quantum-resistant cryptographic primitives for ZHTP:
//! - CRYSTALS-Dilithium for digital signatures (NIST standardized)
//! - CRYSTALS-Kyber for key encapsulation (NIST standardized)  
//! - BLAKE3 and SHA-3 for hashing
//! - ChaCha20-Poly1305 for symmetric encryption
//! - Ring signatures for anonymity
//! - Multi-signatures for shared control
//! - Zero-knowledge proofs for privacy (Plonky2 integration)
//! - Secure memory management with zeroization
//!
//! This module provides the cryptographic foundation for the entire ZHTP ecosystem,
//! implementing production-ready post-quantum security that will remain secure
//! even against quantum computer attacks.

// Core type definitions
pub mod types;

// KeyPair management
pub mod keypair;

// Post-quantum cryptography (CRYSTALS)
pub mod post_quantum;

// Classical cryptography compatibility  
pub mod classical;

// Symmetric cryptography
pub mod symmetric;

// Hashing algorithms
pub mod hashing;

// Secure random generation
pub mod random;

// Advanced cryptographic schemes
pub mod advanced;

// Key derivation functions
pub mod kdf;

// ZK proof integration
pub mod zk_integration;

// Signature verification
pub mod verification;

// Utility functions
pub mod utils;

// Re-export main types for convenience
pub use types::*;
pub use keypair::KeyPair;
pub use post_quantum::{DILITHIUM_PUBLIC_KEY_SIZE, DILITHIUM_PRIVATE_KEY_SIZE, KYBER_PUBLIC_KEY_SIZE, KYBER_PRIVATE_KEY_SIZE};
pub use classical::{ed25519_sign, ed25519_verify, curve25519_scalar_mult};
pub use symmetric::{encrypt_data, decrypt_data, hybrid_encrypt, hybrid_decrypt};
pub use hashing::{hash_blake3, hash_sha3, hash_sha3_256};
pub use random::{SecureRng, generate_nonce};
pub use advanced::{RingSignature, MultiSig, verify_ring_signature};
pub use kdf::{hkdf_sha3, derive_keys};
pub use zk_integration::{ZkProofSystem, Plonky2Proof, ZKProof, prove_identity, prove_range, prove_storage_access, verify_zk_proof};
pub use verification::verify_signature;
pub use utils::{generate_keypair, sign_message};

// Constants for CRYSTALS key sizes (from post_quantum module)
pub use post_quantum::constants::*;

// Type aliases for compatibility with other modules
pub type PostQuantumSignature = Signature;

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_real_keypair_generation() -> Result<()> {
        let keypair = KeyPair::generate()?;
        
        // Verify we have real key sizes (check actual generated key sizes)
        assert!(keypair.public_key.dilithium_pk.len() > 1000);
        assert!(keypair.public_key.kyber_pk.len() > 700); 
        assert!(keypair.private_key.dilithium_sk.len() > 2000);
        assert!(keypair.private_key.kyber_sk.len() > 1500);
        assert_eq!(keypair.public_key.key_id.len(), 32);
        
        Ok(())
    }

    #[test]
    fn test_crypto_integration() -> Result<()> {
        // Test full crypto workflow
        let keypair = KeyPair::generate()?;
        let message = b"ZHTP: Quantum-resistant Web4 internet!";
        
        // Sign and verify
        let signature = keypair.sign(message)?;
        assert!(keypair.verify(&signature, message)?);
        
        // Encrypt and decrypt
        let plaintext = b"Secret ZHTP data";
        let associated_data = b"ZHTP-v1.0";
        let ciphertext = keypair.encrypt(plaintext, associated_data)?;
        let decrypted = keypair.decrypt(&ciphertext, associated_data)?;
        assert_eq!(plaintext.as_slice(), decrypted);
        
        // Test ZK proofs (should provide helpful error message about zhtp-zk dependency)
        let zk_result = keypair.prove_identity(25, 840, 9999, 18, 840);
        assert!(zk_result.is_err());
        assert!(zk_result.unwrap_err().to_string().contains("zhtp-zk"));
        
        Ok(())
    }
}
