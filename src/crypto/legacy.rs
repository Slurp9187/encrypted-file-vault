// src/crypto/legacy.rs
use crate::aliases::{CypherText, FileKey32, FilePassword, RandomFileKey32};
use crate::consts::RANDOM_KEY_KDF_ITERATIONS;
use crate::error::CoreError;
use aescrypt_rs::convert::convert_to_v3_ext;
use secure_gate::SecureRandomExt;
use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

use super::encrypt::encrypt_to_vec;

pub type Result<T> = std::result::Result<T, CoreError>;

/// Thread-safe writer required because convert_to_v3_ext demands a 'static writer
#[derive(Clone)]
struct ThreadSafeVec(Arc<Mutex<Vec<u8>>>);

impl Write for ThreadSafeVec {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// One-time migration: legacy v0-v2 file → v3 with a fresh random key
///
/// * `ciphertext`      – original legacy AES-Crypt file (v0-v2)
/// * `old_password`    – password that can decrypt the legacy file
///
/// Returns the new v3 ciphertext (wrapped in our `CypherText` alias) and the
/// freshly-generated random file key (as `FileKey32`).
pub fn upgrade_from_legacy(
    ciphertext: Vec<u8>,
    old_password: &FilePassword,
) -> Result<(CypherText, FileKey32)> {
    // 1. Fresh random 256-bit key – hex form (zeroized on drop)
    let new_password_hex = RandomFileKey32::random_hex();

    // 2. Decode the validated hex back to bytes (guaranteed 32 bytes)
    let new_key_bytes = new_password_hex.to_bytes();

    // 3. Convert Vec<u8> to [u8; 32] – always succeeds (validated length)
    let new_key_arr: [u8; 32] = new_key_bytes
        .try_into()
        .expect("Generated random hex is always 32 bytes");

    // 4. Canonical fixed-size secret for the vault DB
    let new_key = FileKey32::new(new_key_arr);

    // 5. Dynamic password wrapper expected by aescrypt-rs (clone the inner String)
    let new_password = FilePassword::new(new_password_hex.expose_secret().clone());

    // 6. Decrypt legacy file → plaintext (via thread-safe writer)
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = ThreadSafeVec(buffer.clone());

    convert_to_v3_ext(
        Cursor::new(ciphertext),
        writer,
        old_password,        // ← matches the upstream param name
        Some(&new_password), // new random key (optional in ext version)
        RANDOM_KEY_KDF_ITERATIONS,
    )
    .map_err(CoreError::Crypto)?;

    // 7. Grab the plaintext
    let plaintext = std::mem::take(&mut *buffer.lock().unwrap());

    // 8. Re-encrypt with the brand-new random key
    let final_ct = encrypt_to_vec(&plaintext, &new_password)?;

    Ok((CypherText::new(final_ct), new_key))
}
