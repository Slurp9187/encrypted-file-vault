// src/file_ops.rs
//! File-level encryption/decryption operations
//!
//! This module handles encryption and decryption with file I/O,
//! building on the pure crypto primitives from crypto.rs.
//! Also includes AES-Crypt file detection utilities.

use std::path::Path;

use crate::aliases::{CypherText, FilePassword, PlainText};
use crate::crypto::{decrypt_to_vec, encrypt_to_vec};
use crate::error::CoreError;

/// Encrypt a file on disk using AES-Crypt v3
///
/// Reads the plaintext file, encrypts it in-memory, writes the ciphertext.
/// Returns the plaintext size in bytes.
pub fn encrypt_file<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    password: &FilePassword,
) -> Result<u64, CoreError> {
    let plaintext = PlainText::new(std::fs::read(input_path.as_ref())?);
    let ciphertext = encrypt_to_vec(&plaintext, password)?;
    std::fs::write(output_path.as_ref(), ciphertext.expose_secret())?;

    let plaintext_size_bytes = plaintext.expose_secret().len() as u64;
    Ok(plaintext_size_bytes)
}

/// Decrypt an AES-Crypt file on disk
///
/// Reads the ciphertext file, decrypts it in-memory, writes the plaintext.
/// Returns the plaintext size in bytes.
pub fn decrypt_file<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    password: &FilePassword,
) -> Result<u64, CoreError> {
    let ciphertext = CypherText::new(std::fs::read(input_path.as_ref())?);
    let plaintext = decrypt_to_vec(&ciphertext, password)?;
    std::fs::write(output_path.as_ref(), plaintext.expose_secret())?;

    let plaintext_size_bytes = plaintext.expose_secret().len() as u64;
    Ok(plaintext_size_bytes)
}

/// Check if data is an AES-Crypt file (any version)
pub fn is_aescrypt_file(data: &[u8]) -> bool {
    data.starts_with(b"AES")
}

pub fn aescrypt_version(data: &[u8]) -> Option<u8> {
    if is_aescrypt_file(data) && data.len() > 3 {
        Some(data[3])
    } else {
        None
    }
}
