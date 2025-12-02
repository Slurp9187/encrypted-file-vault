// src/core/crypto/decrypt.rs
use crate::aliases::FilePassword;
use crate::error::CoreError;
use aescrypt_rs::decrypt;
use std::io::Cursor;

pub type Result<T> = std::result::Result<T, CoreError>;

/// Decrypt AES-Crypt ciphertext → plaintext (in-memory)
pub fn decrypt_to_vec(ciphertext: &[u8], password: &FilePassword) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    decrypt(Cursor::new(ciphertext), &mut out, password).map_err(CoreError::Crypto)?;
    Ok(out)
}
