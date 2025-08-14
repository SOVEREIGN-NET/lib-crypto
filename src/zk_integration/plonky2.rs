//! Plonky2 zero-knowledge proof integration for ZHTP
//! 
//! Trait-based interface for ZK functionality to avoid circular dependencies.
//! Actual implementation is provided by the zhtp-zk package.

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Plonky2 proof structure for cross-package compatibility
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plonky2Proof {
    pub proof_data: Vec<u8>,
    pub public_inputs: Vec<u64>,
    pub verification_key: Vec<u8>,
    pub circuit_digest: [u8; 32],
}

/// Trait for ZK proof systems to implement
pub trait ZkProofSystem {
    /// Create new ZK proof system
    fn new() -> Result<Self> where Self: Sized;

    /// Prove identity without revealing personal information
    fn prove_identity(
        &self,
        identity_secret: u64,
        age: u64,
        jurisdiction_hash: u64,
        credential_hash: u64,
        min_age: u64,
        required_jurisdiction: u64,
    ) -> Result<Plonky2Proof>;

    /// Prove a value is within a range without revealing the value
    fn prove_range(
        &self,
        value: u64,
        blinding_factor: u64,
        min_value: u64,
        max_value: u64,
    ) -> Result<Plonky2Proof>;

    /// Prove storage access rights without revealing the data
    fn prove_storage_access(
        &self,
        access_key: u64,
        requester_secret: u64,
        data_hash: u64,
        permission_level: u64,
        required_permission: u64,
    ) -> Result<Plonky2Proof>;

    /// Verify identity proof
    fn verify_identity(&self, proof: &Plonky2Proof) -> Result<bool>;

    /// Verify range proof
    fn verify_range(&self, proof: &Plonky2Proof) -> Result<bool>;

    /// Verify storage access proof
    fn verify_storage_access(&self, proof: &Plonky2Proof) -> Result<bool>;
}

/// Default implementation that provides informative error messages
#[derive(Clone, Debug)]
pub struct DefaultZkProofSystem;

impl ZkProofSystem for DefaultZkProofSystem {
    fn new() -> Result<Self> {
        Ok(Self)
    }

    fn prove_identity(
        &self,
        _identity_secret: u64,
        _age: u64,
        _jurisdiction_hash: u64,
        _credential_hash: u64,
        _min_age: u64,
        _required_jurisdiction: u64,
    ) -> Result<Plonky2Proof> {
        Err(anyhow::anyhow!(
            "ZK proof functionality requires the zhtp-zk package. \
            Add zhtp-zk = {{ path = \"../zhtp-zk\" }} to your Cargo.toml \
            and use zhtp_zk::plonky2::ZkProofSystem instead."
        ))
    }

    fn prove_range(
        &self,
        _value: u64,
        _blinding_factor: u64,
        _min_value: u64,
        _max_value: u64,
    ) -> Result<Plonky2Proof> {
        Err(anyhow::anyhow!(
            "ZK proof functionality requires the zhtp-zk package. \
            Add zhtp-zk = {{ path = \"../zhtp-zk\" }} to your Cargo.toml \
            and use zhtp_zk::range::BulletproofRangeProof instead."
        ))
    }

    fn prove_storage_access(
        &self,
        _access_key: u64,
        _requester_secret: u64,
        _data_hash: u64,
        _permission_level: u64,
        _required_permission: u64,
    ) -> Result<Plonky2Proof> {
        Err(anyhow::anyhow!(
            "ZK proof functionality requires the zhtp-zk package. \
            Add zhtp-zk = {{ path = \"../zhtp-zk\" }} to your Cargo.toml \
            and use zhtp_zk::plonky2::ZkProofSystem instead."
        ))
    }

    fn verify_identity(&self, _proof: &Plonky2Proof) -> Result<bool> {
        Err(anyhow::anyhow!(
            "ZK verification requires the zhtp-zk package. \
            Use zhtp_zk::verifiers::identity_verifier instead."
        ))
    }

    fn verify_range(&self, _proof: &Plonky2Proof) -> Result<bool> {
        Err(anyhow::anyhow!(
            "ZK verification requires the zhtp-zk package. \
            Use zhtp_zk::verifiers::range_verifier instead."
        ))
    }

    fn verify_storage_access(&self, _proof: &Plonky2Proof) -> Result<bool> {
        Err(anyhow::anyhow!(
            "ZK verification requires the zhtp-zk package. \
            Use zhtp_zk::verifiers instead."
        ))
    }
}

// Type alias for backward compatibility
pub type ZKProof = Plonky2Proof;

/// Convenience functions using default implementation (provides helpful errors)
pub fn prove_identity(
    _private_key: &crate::types::PrivateKey,
    _age: u64,
    _jurisdiction_hash: u64,
    _credential_hash: u64,
    _min_age: u64,
    _required_jurisdiction: u64,
) -> Result<Plonky2Proof> {
    let zk_system = DefaultZkProofSystem::new()?;
    zk_system.prove_identity(0, _age, _jurisdiction_hash, _credential_hash, _min_age, _required_jurisdiction)
}

pub fn prove_range(
    _value: u64,
    _blinding_factor: u64,
    _min_value: u64,
    _max_value: u64,
) -> Result<Plonky2Proof> {
    let zk_system = DefaultZkProofSystem::new()?;
    zk_system.prove_range(_value, _blinding_factor, _min_value, _max_value)
}

pub fn prove_storage_access(
    _access_key: u64,
    _requester_secret: u64,
    _data_hash: u64,
    _permission_level: u64,
    _required_permission: u64,
) -> Result<Plonky2Proof> {
    let zk_system = DefaultZkProofSystem::new()?;
    zk_system.prove_storage_access(_access_key, _requester_secret, _data_hash, _permission_level, _required_permission)
}

pub fn verify_zk_proof(_proof: &Plonky2Proof) -> Result<bool> {
    let zk_system = DefaultZkProofSystem::new()?;
    zk_system.verify_identity(_proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_zk_system_creation() {
        let result = DefaultZkProofSystem::new();
        assert!(result.is_ok());
    }

    #[test]
    fn test_default_implementations_provide_helpful_errors() {
        let zk_system = DefaultZkProofSystem::new().unwrap();
        
        let identity_result = zk_system.prove_identity(12345, 25, 840, 9999, 18, 840);
        assert!(identity_result.is_err());
        assert!(identity_result.unwrap_err().to_string().contains("zhtp-zk"));
        
        let range_result = zk_system.prove_range(500, 123456, 0, 1000);
        assert!(range_result.is_err());
        assert!(range_result.unwrap_err().to_string().contains("zhtp-zk"));
        
        let storage_result = zk_system.prove_storage_access(11111, 22222, 33333, 5, 3);
        assert!(storage_result.is_err());
        assert!(storage_result.unwrap_err().to_string().contains("zhtp-zk"));
    }

    #[test]
    fn test_convenience_functions_provide_helpful_errors() {
        let private_key = crate::types::PrivateKey {
            dilithium_sk: vec![1, 2, 3, 4, 5, 6, 7, 8],
            kyber_sk: vec![],
            ed25519_sk: vec![],
            master_seed: vec![],
        };
        
        let identity_result = prove_identity(&private_key, 25, 840, 9999, 18, 840);
        assert!(identity_result.is_err());
        assert!(identity_result.unwrap_err().to_string().contains("zhtp-zk"));
        
        let range_result = prove_range(500, 123456, 0, 1000);
        assert!(range_result.is_err());
        assert!(range_result.unwrap_err().to_string().contains("zhtp-zk"));
        
        let storage_result = prove_storage_access(11111, 22222, 33333, 5, 3);
        assert!(storage_result.is_err());
        assert!(storage_result.unwrap_err().to_string().contains("zhtp-zk"));
    }

    #[test]
    fn test_proof_structure() {
        let proof = Plonky2Proof {
            proof_data: vec![1, 2, 3, 4],
            public_inputs: vec![100, 200],
            verification_key: vec![5, 6, 7, 8],
            circuit_digest: [42u8; 32],
        };
        
        assert_eq!(proof.proof_data.len(), 4);
        assert_eq!(proof.public_inputs.len(), 2);
        assert_eq!(proof.verification_key.len(), 4);
        assert_eq!(proof.circuit_digest[0], 42);
    }
}
