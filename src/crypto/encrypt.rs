// src/crypto/encrypt.rs
use crate::aliases::{CypherText, FilePassword, PlainText};
use crate::consts::RANDOM_KEY_KDF_ITERATIONS;
use crate::error::CoreError;
use aescrypt_rs::encrypt;
use std::io::Cursor;

/// Encrypt plaintext → AES-Crypt v3 ciphertext (in-memory)
///
/// Uses `RANDOM_KEY_KDF_ITERATIONS = 1` — correct for 256-bit random keys.
pub fn encrypt_to_vec(
    plaintext: &PlainText,
    password: &FilePassword,
) -> Result<CypherText, CoreError> {
    let mut out = Vec::new();
    encrypt(
        Cursor::new(plaintext.expose_secret()),
        &mut out,
        password,
        RANDOM_KEY_KDF_ITERATIONS,
    )
    .map_err(CoreError::Crypto)?;
    Ok(CypherText::new(out))
}
