// src/crypto/legacy.rs
use crate::aliases::{
    FileKey32, FilePassword, RandomFileKey32, SecureConversionsExt, SecureRandomExt,
};
use crate::consts::{AESCRYPT_V3_HEADER, RANDOM_KEY_KDF_ITERATIONS};
use crate::error::CoreError;
use aescrypt_rs::convert::convert_to_v3_ext;
use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

pub type Result<T> = std::result::Result<T, CoreError>;

/// Thread-safe writer for convert_to_v3 (required due to 'static bound on W)
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

/// Upgrade legacy v0-v2 → v3 if needed, otherwise pass through
pub fn ensure_v3(ciphertext: Vec<u8>, password: &FilePassword) -> Result<Vec<u8>> {
    if ciphertext.get(..5) == Some(AESCRYPT_V3_HEADER.as_slice()) {
        return Ok(ciphertext);
    }

    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = ThreadSafeVec(buffer.clone());

    convert_to_v3_ext(
        Cursor::new(ciphertext),
        writer,
        password,
        Some(password),
        RANDOM_KEY_KDF_ITERATIONS,
    )
    .map_err(CoreError::Crypto)?;

    let result = std::mem::take(&mut *buffer.lock().unwrap());
    Ok(result)
}

/// One-time migration: legacy file → v3 with fresh random key
pub fn upgrade_from_legacy(
    ciphertext: Vec<u8>,
    legacy_password: &FilePassword,
) -> Result<(Vec<u8>, FileKey32)> {
    let random_key = RandomFileKey32::new();
    let new_password = FilePassword::new(random_key.expose_secret().to_hex());
    let new_key = FileKey32::new(**random_key);

    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = ThreadSafeVec(buffer.clone());

    convert_to_v3_ext(
        Cursor::new(ciphertext),
        writer,
        legacy_password,
        Some(&new_password),
        RANDOM_KEY_KDF_ITERATIONS,
    )
    .map_err(CoreError::Crypto)?;

    let final_ct = std::mem::take(&mut *buffer.lock().unwrap());

    Ok((final_ct, new_key))
}
