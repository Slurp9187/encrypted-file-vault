// src/legacy/upgrade.rs
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

use crate::aliases::{
    FileKey32, FilePassword, RandomFileKey32, SecureConversionsExt, SecureRandomExt,
};
use aescrypt_rs::convert::convert_to_v3_ext;
use aescrypt_rs::AescryptError;

/// Upgrade a legacy AES-Crypt v0–v2 file → v3 using a fresh random key
pub fn upgrade_from_legacy(
    input_path: &Path,
    output_path: &Path,
    legacy_password: &FilePassword,
) -> Result<FileKey32, AescryptError> {
    let input = BufReader::new(File::open(input_path)?);
    let output = BufWriter::new(File::create(output_path)?);

    let random_key = RandomFileKey32::new();
    let new_password = FilePassword::new(random_key.expose_secret().to_hex());
    let new_key = FileKey32::new(**random_key);

    convert_to_v3_ext(input, output, legacy_password, Some(&new_password), 600_000)?;

    Ok(new_key)
}
