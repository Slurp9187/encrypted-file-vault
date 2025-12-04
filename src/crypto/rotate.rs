use secure_gate::SecureRandomExt;

// src/crypto/rotate.rs
use crate::aliases::{CypherText, FileKey32, FilePassword, PlainText, RandomFileKey32};
use crate::error::CoreError;

use super::{decrypt_to_vec, encrypt_to_vec, legacy::upgrade_from_legacy};

pub type Result<T> = std::result::Result<T, CoreError>;

pub fn rotate_key(
    ciphertext: &CypherText,
    old_password: &FilePassword,
) -> Result<(CypherText, FileKey32)> {
    let (new_ciphertext, new_key) = if ciphertext.expose_secret().starts_with(b"AES\x03") {
        let plaintext: PlainText = decrypt_to_vec(ciphertext, old_password)?;
        let new_password_hex = RandomFileKey32::random_hex();
        let new_key_bytes = new_password_hex.to_bytes();
        let new_key_arr: [u8; 32] = new_key_bytes.try_into().expect("random hex → 32 bytes");
        let new_key = FileKey32::new(new_key_arr);
        let new_password = FilePassword::new(new_password_hex.expose_secret().clone());
        let new_ct = encrypt_to_vec(&plaintext, &new_password)?;
        (new_ct, new_key)
    } else {
        let (ct, key) = upgrade_from_legacy(ciphertext.clone(), old_password)?;
        (ct, key)
    };

    Ok((new_ciphertext, new_key))
}
