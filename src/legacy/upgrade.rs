// src/legacy/upgrade.rs
//! Legacy AES-Crypt v0–v2 → v3 migration tool
//!
//! This module is for **one-time upgrades only** — converting files encrypted
//! with human-entered passwords (legacy aescrypt) into the modern vault format
//! using strong random 256-bit keys.

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

use crate::aliases::{FileKey32, FilePassword, SecureConversionsExt, SecureRandomExt};
use aescrypt_rs::convert::convert_to_v3;

/// Upgrade a legacy AES-Crypt v0–v2 file to v3 using a **human-entered password**
/// and re-encrypt it with a fresh random 256-bit key.
///
/// This function is intended for migration only — it does **not** require
/// knowledge of the current vault key (because legacy files don't have one).
///
/// Returns the new random `FileKey32` that must be stored in the vault.
pub fn upgrade_from_legacy(
    input_path: &Path,
    output_path: &Path,
    legacy_password: &FilePassword,
) -> Result<FileKey32, aescrypt_rs::AescryptError> {
    let input = BufReader::new(File::open(input_path)?);
    let output = BufWriter::new(File::create(output_path)?);

    let new_key = FileKey32::random();
    let new_password = FilePassword::new(new_key.expose_secret().to_hex());

    convert_to_v3(
        input,
        output,
        &new_password.as_str().into(), // &str → aescrypt_rs accepts &str
        600_000,                       // slow KDF — safe for random key
    )?;

    Ok(new_key)
}
