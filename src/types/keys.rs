//! Key type definitions - preserving real ZHTP key structures
//! 
//! Real implementations from crypto.rs, lines 78-150

use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use anyhow::Result;
use crate::types::{Signature, SignatureAlgorithm};
use crate::hashing::hash_blake3;
use crate::verification::verify_signature;

/// Real quantum-resistant public key with CRYSTALS implementations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PublicKey {
    /// CRYSTALS-Dilithium public key for post-quantum signatures
    pub dilithium_pk: Vec<u8>,
    /// CRYSTALS-Kyber public key for post-quantum key encapsulation
    pub kyber_pk: Vec<u8>,
    /// Ed25519 public key for compatibility and ring signatures
    pub ed25519_pk: Vec<u8>,
    /// Key identifier for fast lookups
    pub key_id: [u8; 32],
}

impl PublicKey {
    /// Create a new public key from raw bytes (assumes Dilithium)
    pub fn new(dilithium_pk: Vec<u8>) -> Self {
        let key_id = hash_blake3(&dilithium_pk);
        PublicKey {
            dilithium_pk,
            kyber_pk: Vec::new(),
            ed25519_pk: Vec::new(),
            key_id,
        }
    }

    /// Convert public key to bytes for signature verification
    pub fn as_bytes(&self) -> Vec<u8> {
        // For Dilithium signatures, use Dilithium public key
        if !self.dilithium_pk.is_empty() {
            return self.dilithium_pk.clone();
        }
        
        // For backward compatibility, use Ed25519 key if available
        if !self.ed25519_pk.is_empty() {
            return self.ed25519_pk.clone();
        }
        
        // Fallback to key_id
        self.key_id.to_vec()
    }

    /// Verify a signature against this public key using post-quantum cryptography
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<bool> {
        match signature.algorithm {
            SignatureAlgorithm::Dilithium5 => {
                // Use Dilithium verification for post-quantum security
                if self.dilithium_pk.is_empty() {
                    return Err(anyhow::anyhow!("No Dilithium public key available for verification"));
                }
                verify_signature(message, &signature.signature, &self.dilithium_pk)
            },
            SignatureAlgorithm::Ed25519 => {
                // Fallback Ed25519 verification for compatibility
                if self.ed25519_pk.is_empty() {
                    return Err(anyhow::anyhow!("No Ed25519 public key available for verification"));
                }
                verify_signature(message, &signature.signature, &self.ed25519_pk)
            },
            _ => {
                // For any other algorithm, use generic verification
                verify_signature(message, &signature.signature, &self.dilithium_pk)
            }
        }
    }
}

/// Real quantum-resistant private key (zeroized on drop for security)
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    /// CRYSTALS-Dilithium secret key
    pub dilithium_sk: Vec<u8>,
    /// CRYSTALS-Kyber secret key  
    pub kyber_sk: Vec<u8>,
    /// Ed25519 secret key for compatibility
    pub ed25519_sk: Vec<u8>,
    /// Master seed for key derivation
    pub master_seed: Vec<u8>,
}
