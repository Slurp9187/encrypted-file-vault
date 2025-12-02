// src/core/crypto.rs
//! Pure cryptographic primitives — no I/O, no database
//!
//! This module contains only the raw encryption/decryption logic
//! using aescrypt-rs. Everything here works on in-memory buffers.

use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

use crate::aliases::FilePassword;
use aescrypt_rs::{convert::convert_to_v3, decrypt, encrypt};

use crate::aliases::{FileKey32, SecureConversionsExt, SecureRandomExt};
use crate::consts::{AESCRYPT_V3_HEADER, RANDOM_KEY_KDF_ITERATIONS};
use crate::error::CoreError;

pub type Result<T> = std::result::Result<T, CoreError>;

/// Thread-safe writer required because `convert_to_v3` takes the writer by value
#[derive(Clone)]
pub(crate) struct ThreadSafeVec(Arc<Mutex<Vec<u8>>>);

impl Write for ThreadSafeVec {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Encrypt plaintext in memory → returns AES-Crypt v3 ciphertext
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

/// Decrypt ciphertext in memory → returns plaintext
pub fn decrypt_to_vec(ciphertext: &[u8], password: &FilePassword) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    decrypt(Cursor::new(ciphertext), &mut out, password).map_err(CoreError::Crypto)?;
    Ok(out)
}

/// Upgrade legacy AES-Crypt v0–v2 → v3 if needed, otherwise pass through
pub fn ensure_v3(ciphertext: Vec<u8>, password: &FilePassword) -> Result<Vec<u8>> {
    if ciphertext.get(..5) == Some(AESCRYPT_V3_HEADER.as_slice()) {
        return Ok(ciphertext);
    }

    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = ThreadSafeVec(buffer.clone());

    convert_to_v3(
        Cursor::new(ciphertext),
        writer,
        password,
        RANDOM_KEY_KDF_ITERATIONS,
    )
    .map_err(CoreError::Crypto)?;

    // Extract before the lock drops
    let result = std::mem::take(&mut *buffer.lock().unwrap());
    Ok(result)
}

/// Pure cryptographic key rotation — no file I/O, no DB
pub fn rotate_key(ciphertext: &[u8], old_password: &FilePassword) -> Result<(Vec<u8>, FileKey32)> {
    let v3 = ensure_v3(ciphertext.to_vec(), old_password)?;
    let plaintext = decrypt_to_vec(&v3, old_password)?;
    let new_key = FileKey32::random();
    let new_password = FilePassword::new(new_key.expose_secret().to_hex());
    let new_ciphertext = encrypt_to_vec(&plaintext, &new_password)?;
    Ok((new_ciphertext, new_key))
}
