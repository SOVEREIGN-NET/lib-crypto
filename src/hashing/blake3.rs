//! BLAKE3 hashing - preserving real ZHTP fast hashing
//! 
//! Real implementation from crypto.rs, lines 639-642

use blake3::Hasher as Blake3Hasher;

/// Fast cryptographic hash using BLAKE3 (faster than SHA-3)
pub fn hash_blake3(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}
