use secure_gate::SecureRandomExt;

// src/crypto/rotate.rs
use crate::aliases::{CypherText, FileKey32, FilePassword, RandomFileKey32};
use crate::error::CoreError;

use super::{decrypt_to_vec, encrypt_to_vec, legacy::upgrade_from_legacy};

pub type Result<T> = std::result::Result<T, CoreError>;

/// Pure in-memory key rotation: old password → new random key
///
/// Works for both legacy v0–v2 and modern v3 files.
/// - Legacy → upgraded with fresh 256-bit random key
/// - v3 → decrypted and re-encrypted with fresh 256-bit random key
///
/// Returns the new v3 ciphertext (as `Vec<u8>`) and the fresh `FileKey32`.
pub fn rotate_key(ciphertext: &[u8], old_password: &FilePassword) -> Result<(Vec<u8>, FileKey32)> {
    let (new_ciphertext, new_key) = if ciphertext.starts_with(b"AES\x03") {
        // Already v3 → decrypt + re-encrypt with fresh random key
        let plaintext = decrypt_to_vec(ciphertext, old_password)?;

        let new_password_hex = RandomFileKey32::random_hex();
        let new_key_bytes = new_password_hex.to_bytes();
        let new_key_arr: [u8; 32] = new_key_bytes
            .try_into()
            .expect("RandomFileKey32::random_hex() always yields 64 hex chars → 32 bytes");

        let new_key = FileKey32::new(new_key_arr);
        let new_password = FilePassword::new(new_password_hex.expose_secret().clone());

        let new_ct = encrypt_to_vec(&plaintext, &new_password)?;
        (CypherText::new(new_ct), new_key)
    } else {
        // Legacy v0-v2 → use the proven upgrade path
        upgrade_from_legacy(ciphertext.to_vec(), old_password)?
    };

    // CypherText → Vec<u8> via into_inner() → deref to unbox
    Ok((*new_ciphertext.into_inner(), new_key))
}
