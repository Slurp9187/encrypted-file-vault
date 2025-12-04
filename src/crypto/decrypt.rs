// src/core/crypto/decrypt.rs
use crate::aliases::{CypherText, FilePassword, PlainText};
use crate::error::CoreError;
use aescrypt_rs::decrypt;
use std::io::Cursor;

pub type Result<T> = std::result::Result<T, CoreError>;

/// Decrypt AES-Crypt ciphertext → plaintext (in-memory)
///
/// Returns `PlainText` — a secure-gate `Dynamic<Vec<u8>>` that auto-zeroizes on drop.
pub fn decrypt_to_vec(ciphertext: &CypherText, password: &FilePassword) -> Result<PlainText> {
    let mut out = Vec::new();
    decrypt(Cursor::new(ciphertext.expose_secret()), &mut out, password)
        .map_err(CoreError::Crypto)?;
    Ok(PlainText::new(out))
}
