// src/rotation/v3.rs
//! Pure key rotation for AES-Crypt v3 files using known hex keys
//!
//! This is a core vault maintenance operation — used by CLI tools,
//! batch rotators, and `rotate_key_in_vault`.

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

use crate::aliases::{FileKey32, FilePassword, SecureConversionsExt, SecureRandomExt};
use aescrypt_rs::{decrypt, encrypt};

/// Rotate the encryption key on an existing v3 file using the **current known key**
///
/// This is the secure, production-grade rotation path when you already have
/// the current `FileKey32` in hex form (from the vault DB).
///
/// Returns the new random `FileKey32` that must be stored in the vault.
pub fn rotate_key(
    input_path: &Path,
    output_path: &Path,
    current_key_hex: &FilePassword,
) -> Result<FileKey32, aescrypt_rs::AescryptError> {
    let input = BufReader::new(File::open(input_path)?);

    // Decrypt to secure temporary file
    let temp_decrypted = tempfile::Builder::new()
        .prefix("efv-rotate-decrypted-")
        .tempfile()?;

    decrypt(
        input,
        BufWriter::new(&temp_decrypted),
        &current_key_hex.as_str().into(),
    )?;

    // Generate new key and re-encrypt
    let new_key = FileKey32::random();
    let new_password = FilePassword::new(new_key.expose_secret().to_hex());

    let decrypted_reopen = temp_decrypted.reopen()?;
    let final_output = BufWriter::new(File::create(output_path)?);

    encrypt(
        decrypted_reopen,
        final_output,
        &new_password.as_str().into(),
        600_000,
    )?;

    Ok(new_key)
}
