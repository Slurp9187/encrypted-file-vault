// src/crypto/legacy.rs
use crate::aliases::{CypherText, FileKey32, FilePassword, PlainText, RandomFileKey32};
use crate::consts::RANDOM_KEY_KDF_ITERATIONS;
use crate::error::CoreError;
use aescrypt_rs::convert::convert_to_v3_ext;
use secure_gate::SecureRandomExt;
use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

use super::encrypt::encrypt_to_vec;

pub type Result<T> = std::result::Result<T, CoreError>;

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
pub fn upgrade_from_legacy(
    ciphertext: CypherText,
    old_password: &FilePassword,
) -> Result<(CypherText, FileKey32)> {
    let new_password_hex = RandomFileKey32::random_hex();
    let new_key_bytes = new_password_hex.to_bytes();
    let new_key_arr: [u8; 32] = new_key_bytes
        .try_into()
        .expect("random_hex always yields 64 chars → 32 bytes");
    let new_key = FileKey32::new(new_key_arr);
    let new_password = FilePassword::new(new_password_hex.expose_secret().clone());

    // Extract Box<Vec<u8>> and leak it to make it 'static
    let leaked: &'static [u8] = Box::leak(ciphertext.into_inner()).as_slice();

    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = ThreadSafeVec(buffer.clone());

    convert_to_v3_ext(
        Cursor::new(leaked),
        writer,
        old_password,
        Some(&new_password),
        RANDOM_KEY_KDF_ITERATIONS,
    )
    .map_err(CoreError::Crypto)?;

    let plaintext_vec = std::mem::take(&mut *buffer.lock().unwrap());
    let plaintext = PlainText::new(plaintext_vec);
    let final_ct = encrypt_to_vec(&plaintext, &new_password)?;

    // Don't forget to clean up the leak!
    unsafe {
        Box::from_raw(leaked.as_ptr() as *mut Vec<u8>);
    }

    Ok((final_ct, new_key))
}
