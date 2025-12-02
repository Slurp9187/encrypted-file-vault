// src/core/crypto/mod.rs
//! Pure cryptographic operations — no I/O, no database
//!
//! All functions work exclusively on in-memory buffers.
//! Designed for maximum clarity, testability, and future algorithm support.
mod decrypt;
mod encrypt;
mod legacy;
mod rotate;

pub use decrypt::decrypt_to_vec;
pub use encrypt::encrypt_to_vec;
pub use legacy::{ensure_v3, upgrade_from_legacy};
pub use rotate::rotate_key;
