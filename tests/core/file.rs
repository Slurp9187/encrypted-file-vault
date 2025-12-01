// tests/core/file.rs
use encrypted_file_vault::aliases::FilePassword;
use encrypted_file_vault::core::{decrypt_file, encrypt_file, generate_key};
use encrypted_file_vault::SecureConversionsExt;
use std::fs;
use tempfile::tempdir; // This is the missing line!

#[test]
fn test_encrypt_file_and_decrypt_file_roundtrip() {
    let dir = tempdir().unwrap();
    let plain = dir.path().join("plain.txt");
    let enc = dir.path().join("secret.aes");
    let dec = dir.path().join("out.txt");

    fs::write(&plain, b"The quick brown fox jumps over the lazy dog").unwrap();

    let password = FilePassword::new(
        generate_key() // returns FileKey32
            .expose_secret() // -> &[u8; 32]
            .to_hex(), // now works! because trait is in scope
    );

    let size1 = encrypt_file(&plain, &enc, &password).unwrap();
    let size2 = decrypt_file(&enc, &dec, &password).unwrap();

    assert_eq!(size1, size2);
    assert_eq!(fs::read(&dec).unwrap(), fs::read(&plain).unwrap());
}
