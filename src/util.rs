//! Small utility functions used across the core module
//!
//! This includes hashing helpers and other misc utilities.
//! Keep this light — if it grows, split further.

use blake3::Hasher;

/// Compute BLAKE3 hash and return as lowercase hex string
pub fn blake3_hex(data: &[u8]) -> String {
    Hasher::new().update(data).finalize().to_hex().to_string()
}
