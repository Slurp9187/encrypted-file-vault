// src/crypto/rotate.rs
use crate::aliases::{
    FileKey32, FilePassword, RandomFileKey32, SecureConversionsExt, SecureRandomExt,
};
use crate::error::CoreError;

use super::{decrypt_to_vec, encrypt_to_vec, ensure_v3};

pub type Result<T> = std::result::Result<T, CoreError>;

/// Pure in-memory key rotation: old password → new random key
pub fn rotate_key(ciphertext: &[u8], old_password: &FilePassword) -> Result<(Vec<u8>, FileKey32)> {
    let v3 = ensure_v3(ciphertext.to_vec(), old_password)?;
    let plaintext = decrypt_to_vec(&v3, old_password)?;
    let random_key = RandomFileKey32::new();
    let new_password = FilePassword::new(random_key.expose_secret().to_hex());
    let new_key = FileKey32::new(**random_key);
    let new_ciphertext = encrypt_to_vec(&plaintext, &new_password)?;
    Ok((new_ciphertext, new_key))
}
