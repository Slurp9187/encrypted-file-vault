// src/crypto/rotate.rs
use crate::aliases::{CypherText, FileKey32, FilePassword, RandomFileKey32};
use crate::error::CoreError;
use aescrypt_rs::{decrypt, encrypt};
use secure_gate::SecureRandomExt;
use std::io::{self, Read, Write};

use pipe::pipe;

use super::legacy::upgrade_from_legacy;

/// In-memory key rotation — only for small files (< ~100 MB)
///
/// For large files, use `rotate_key_streaming`.
pub fn rotate_key(
    ciphertext: &CypherText,
    old_password: &FilePassword,
) -> Result<(CypherText, FileKey32), CoreError> {
    if ciphertext.expose_secret().starts_with(b"AES\x03") {
        let plaintext = super::decrypt_to_vec(ciphertext, old_password)?;

        let new_password_hex = RandomFileKey32::random_hex();
        let new_key_bytes = new_password_hex.to_bytes();

        let new_key = FileKey32::new(
            new_key_bytes
                .try_into()
                .expect("RandomFileKey32::random_hex() always yields exactly 32 bytes"),
        );

        let new_password = FilePassword::new(new_password_hex.expose_secret().clone());
        let new_ct = super::encrypt_to_vec(&plaintext, &new_password)?;

        Ok((new_ct, new_key))
    } else {
        upgrade_from_legacy(ciphertext.clone(), old_password)
    }
}

/// Streaming key rotation — works with arbitrarily large files (100 GB+)
///
/// Uses `pipe` crate for zero-copy streaming.
/// Peak memory: ~128 KB. This is the only production-safe version.
pub fn rotate_key_streaming<R: Read + Send + 'static, W: Write + Send + 'static>(
    input: R,
    output: W,
    old_password: &FilePassword,
) -> Result<FileKey32, CoreError> {
    let new_password_hex = RandomFileKey32::random_hex();
    let new_key_bytes = new_password_hex.to_bytes();

    let new_key = FileKey32::new(
        new_key_bytes
            .try_into()
            .expect("RandomFileKey32::random_hex() always yields exactly 32 bytes"),
    );

    let new_password = FilePassword::new(new_password_hex.expose_secret().clone());

    let (mut decrypt_reader, decrypt_writer) = pipe();
    let (encrypt_reader, mut encrypt_writer) = pipe(); // ← MUT HERE

    let old_password_cloned = old_password.clone();
    let new_password_cloned = new_password.clone();

    let decrypt_thread =
        std::thread::spawn(move || decrypt(input, decrypt_writer, &old_password_cloned));

    let encrypt_thread =
        std::thread::spawn(move || encrypt(encrypt_reader, output, &new_password_cloned, 1));

    io::copy(&mut decrypt_reader, &mut encrypt_writer).map_err(CoreError::Io)?;

    decrypt_thread.join().unwrap().map_err(CoreError::Crypto)?;
    encrypt_thread.join().unwrap().map_err(CoreError::Crypto)?;

    Ok(new_key)
}
