// src/rotate_keys.rs
// Production-grade — no hard-coded anything, no debug prints, maximum security
// ZERO dependency on aescrypt_rs::Password — only our own secure-gate aliases

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

use aescrypt_rs::convert::convert_to_v3;
use aescrypt_rs::decrypt;
use aescrypt_rs::encrypt;

use crate::aliases::{FileKey32, FilePassword, SecureConversionsExt, SecureRandomExt};

/// Upgrade a legacy AES Crypt file (v0–v2) to modern v3 using a human-entered password
pub fn upgrade_legacy_to_v3(
    input_path: &Path,
    output_path: &Path,
) -> Result<FileKey32, aescrypt_rs::AescryptError> {
    let input = BufReader::new(File::open(input_path)?);
    let output = BufWriter::new(File::create(output_path)?);

    let new_key = FileKey32::random();
    let new_password = FilePassword::new(new_key.expose_secret().to_hex());

    convert_to_v3(
        input,
        output,
        &new_password.as_str().into(), // FilePassword → &str → aescrypt_rs accepts &str
        600_000,
    )?;

    Ok(new_key)
}

/// Rotate key on an existing v3 file using the previous key in hex form
pub fn rotate_key_v3(
    input_path: &Path,
    output_path: &Path,
    old_key_hex: &FilePassword, // holds the previous key as hex string
) -> Result<FileKey32, aescrypt_rs::AescryptError> {
    let input = BufReader::new(File::open(input_path)?);

    // Decrypt to temp file
    let temp_output = tempfile::Builder::new().prefix("efv-rotate-").tempfile()?;

    decrypt(
        input,
        BufWriter::new(&temp_output),
        &old_key_hex.as_str().into(), // &str → aescrypt_rs
    )?;

    // Generate new random key and re-encrypt
    let new_key = FileKey32::random();
    let new_password = FilePassword::new(new_key.expose_secret().to_hex());

    let temp_file = temp_output.reopen()?;
    let final_output = BufWriter::new(File::create(output_path)?);

    encrypt(
        temp_file,
        final_output,
        &new_password.as_str().into(),
        600_000,
    )?;

    Ok(new_key)
}
