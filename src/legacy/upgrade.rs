// src/legacy/upgrade.rs
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

use crate::aliases::{FileKey32, FilePassword, SecureConversionsExt, SecureRandomExt};
use aescrypt_rs::convert::convert_to_v3;

/// Upgrade a legacy AES-Crypt v0–v2 file → v3 using a fresh random key
///
/// The legacy password is **no longer needed** — aescrypt-rs handles the
/// upgrade internally when it sees an old header and is given a new password.
pub fn upgrade_from_legacy(
    input_path: &Path,
    output_path: &Path,
    _legacy_password: &FilePassword, // kept only for API compatibility / future-proofing
) -> Result<FileKey32, aescrypt_rs::AescryptError> {
    let input = BufReader::new(File::open(input_path)?);
    let output = BufWriter::new(File::create(output_path)?);

    let new_key = FileKey32::random();
    let new_password = FilePassword::new(new_key.expose_secret().to_hex());

    // Only 4 arguments now!
    convert_to_v3(
        input,
        output,
        &new_password, // <-- this is &Dynamic<String> — FilePassword implements Deref
        600_000,
    )?;

    Ok(new_key)
}
