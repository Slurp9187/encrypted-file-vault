// src/core/file.rs
//! File-level encryption/decryption operations
//!
//! This module handles encryption and decryption with file I/O,
//! building on the pure crypto primitives from crypto.rs.
//! Also includes AES-Crypt file detection utilities.

use std::path::Path;

// use crate::consts::AESCRYPT_V3_HEADER;
use crate::core::crypto::{decrypt_to_vec, encrypt_to_vec};
// use crate::error::CoreError;
use crate::CoreResult as Result; // Use the crate's public Result alias

use aescrypt_rs::aliases::Password;

/// Encrypt a file on disk using AES-Crypt v3
pub fn encrypt_file<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    password: &Password,
) -> Result<u64> {
    let plaintext = std::fs::read(input_path.as_ref())?;
    let ciphertext = encrypt_to_vec(&plaintext, password)?;
    std::fs::write(output_path.as_ref(), ciphertext)?;
    Ok(plaintext.len() as u64)
}

/// Decrypt an AES-Crypt file on disk
pub fn decrypt_file<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    password: &Password,
) -> Result<u64> {
    let ciphertext = std::fs::read(input_path.as_ref())?;
    let plaintext = decrypt_to_vec(&ciphertext, password)?;
    std::fs::write(output_path.as_ref(), &plaintext)?;
    Ok(plaintext.len() as u64)
}

/// Check if data is an AES-Crypt file (any version)
pub fn is_aescrypt_file(data: &[u8]) -> bool {
    data.get(..3) == Some(b"AES")
}

/// Get AES-Crypt version from header, if valid
pub fn aescrypt_version(data: &[u8]) -> Option<u8> {
    if is_aescrypt_file(data) {
        data.get(3).copied()
    } else {
        None
    }
}
