//! Secure random generation module
//! 
//! Real implementations from crypto.rs preserving secure entropy sources

pub mod secure_rng;
pub mod nonce;

// Re-export main types and functions
pub use secure_rng::SecureRng;
pub use nonce::generate_nonce;
