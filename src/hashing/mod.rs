//! Hashing algorithms module
//! 
//! Real implementations from crypto.rs preserving working hash functions

pub mod blake3;
pub mod sha3;

// Re-export main functions
pub use blake3::hash_blake3;
pub use sha3::{hash_sha3, hash_sha3_256};
