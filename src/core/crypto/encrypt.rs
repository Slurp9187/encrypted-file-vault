// src/core/crypto/encrypt.rs
use crate::aliases::FilePassword;
use crate::consts::RANDOM_KEY_KDF_ITERATIONS;
use crate::error::CoreError;
use aescrypt_rs::encrypt;
use std::io::Cursor;

pub type Result<T> = std::result::Result<T, CoreError>;

/// Encrypt plaintext → AES-Crypt v3 ciphertext (in-memory)
pub fn encrypt_to_vec(plaintext: &[u8], password: &FilePassword) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encrypt(
        Cursor::new(plaintext),
        &mut out,
        password,
        RANDOM_KEY_KDF_ITERATIONS,
    )
    .map_err(CoreError::Crypto)?;
    Ok(out)
}
