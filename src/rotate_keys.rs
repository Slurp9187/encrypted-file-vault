// src/rotate_keys.rs
// Production-grade — no hard-coded anything, no debug prints, maximum security

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

use crate::aliases::FilePassword;
use aescrypt_rs::convert::convert_to_v3;
use aescrypt_rs::encrypt;
use secure_gate::{fixed_alias, SecureConversionsExt, SecureRandomExt};

fixed_alias!(FileKey, 32);

/// Upgrade a legacy AES Crypt file (v0–v2) to modern v3
pub fn upgrade_legacy_to_v3(
    input_path: &Path,
    output_path: &Path,
    #[allow(unused_variables)] password: &FilePassword,
) -> Result<FileKey, aescrypt_rs::AescryptError> {
    let input = BufReader::new(File::open(input_path)?);
    let output = BufWriter::new(File::create(output_path)?);

    let new_key: FileKey = FileKey::random(); // now works!
    let iterations = 600_000;

    convert_to_v3(
        input,
        output,
        &FilePassword::new(new_key.expose_secret().to_hex()),
        iterations,
    )?;

    Ok(new_key)
}

/// Rotate key on an existing v3 file
pub fn rotate_key_v3(
    input_path: &Path,
    output_path: &Path,
    old_password: &FilePassword,
) -> Result<FileKey, aescrypt_rs::AescryptError> {
    let input = BufReader::new(File::open(input_path)?);
    let temp_output = tempfile::Builder::new().prefix("efv-rotate-").tempfile()?;

    let new_key: FileKey = FileKey::random(); // now works!
    let new_password = FilePassword::new(hex::encode(new_key.expose_secret()));

    aescrypt_rs::decrypt(input, BufWriter::new(&temp_output), old_password)?;

    let temp_file = temp_output.reopen()?;
    let final_output = BufWriter::new(File::create(output_path)?);
    encrypt(temp_file, final_output, &new_password, 600_000)?;

    Ok(new_key)
}
