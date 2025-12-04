// tests/crypto_tests.rs
use encrypted_file_vault::aliases::{FilePassword, PlainText};
use encrypted_file_vault::consts::AESCRYPT_V3_HEADER;
use encrypted_file_vault::crypto::*;
use encrypted_file_vault::error::CoreError;
use encrypted_file_vault::file_ops::{aescrypt_version, is_aescrypt_file};
use encrypted_file_vault::key_ops::generate_key;
use secure_gate::SecureConversionsExt;

#[test]
fn test_encrypt_decrypt_roundtrip_in_memory() {
    let plaintext = PlainText::new(b"Attack at dawn!".to_vec());
    let key = generate_key();
    let password = FilePassword::new(key.expose_secret().to_hex());

    let ciphertext = encrypt_to_vec(&plaintext, &password).unwrap();
    let decrypted = decrypt_to_vec(&ciphertext, &password).unwrap();

    assert!(ciphertext.expose_secret().starts_with(b"AES"));
    assert_eq!(plaintext.expose_secret(), decrypted.expose_secret());
}

#[test]
fn test_encrypt_to_vec_produces_v3_header() {
    let plaintext = PlainText::new(b"small".to_vec());
    let password = FilePassword::new(generate_key().expose_secret().to_hex());

    let ciphertext = encrypt_to_vec(&plaintext, &password).unwrap();
    assert_eq!(&ciphertext.expose_secret()[..5], *AESCRYPT_V3_HEADER);
}

#[test]
fn test_is_aescrypt_file_and_version() {
    let plaintext = PlainText::new(b"test".to_vec());
    let password = FilePassword::new(generate_key().expose_secret().to_hex());

    let ciphertext = encrypt_to_vec(&plaintext, &password).unwrap();

    assert!(is_aescrypt_file(ciphertext.expose_secret()));
    assert!(!is_aescrypt_file(b"not aes"));
    assert_eq!(aescrypt_version(ciphertext.expose_secret()), Some(3));
}

#[test]
fn test_rotate_key_produces_different_ciphertext_and_new_key() {
    let plaintext = PlainText::new(b"secret message".to_vec());
    let old_key = generate_key();
    let old_password = FilePassword::new(old_key.expose_secret().to_hex());

    let original = encrypt_to_vec(&plaintext, &old_password).unwrap();
    let (new_ciphertext, new_key) = rotate_key(&original, &old_password).unwrap();

    assert_ne!(original.expose_secret(), new_ciphertext.expose_secret());
    assert_ne!(
        old_key.expose_secret().as_slice(),
        new_key.expose_secret().as_slice()
    );

    let decrypted = decrypt_to_vec(
        &new_ciphertext,
        &FilePassword::new(new_key.expose_secret().to_hex()),
    )
    .unwrap();
    assert_eq!(plaintext.expose_secret(), decrypted.expose_secret());
}

#[test]
fn test_decrypt_fails_with_wrong_password() {
    let plaintext = PlainText::new(b"secret".to_vec());
    let key1 = generate_key();
    let key2 = generate_key();

    let ciphertext = encrypt_to_vec(
        &plaintext,
        &FilePassword::new(key1.expose_secret().to_hex()),
    )
    .unwrap();

    let wrong = decrypt_to_vec(
        &ciphertext,
        &FilePassword::new(key2.expose_secret().to_hex()),
    );
    assert!(wrong.is_err());
    assert!(matches!(wrong, Err(CoreError::Crypto(_))));
}
