// tests/core/crypto.rs
use encrypted_file_vault::aliases::FilePassword;
use encrypted_file_vault::consts::AESCRYPT_V3_HEADER;
use encrypted_file_vault::crypto::*;
use encrypted_file_vault::error::CoreError;
use encrypted_file_vault::file_ops::{aescrypt_version, is_aescrypt_file};
use encrypted_file_vault::key_ops::generate_key;
use encrypted_file_vault::SecureConversionsExt;

#[test]
fn test_encrypt_decrypt_roundtrip_in_memory() {
    let plaintext = b"Attack at dawn!";
    let key = generate_key();
    let password = FilePassword::new(key.expose_secret().to_hex());
    let ciphertext = encrypt_to_vec(plaintext, &password).unwrap();
    let decrypted = decrypt_to_vec(&ciphertext, &password).unwrap();
    assert!(ciphertext.starts_with(b"AES"));
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

#[test]
fn test_encrypt_to_vec_produces_v3_header() {
    let ciphertext = encrypt_to_vec(
        b"small",
        &FilePassword::new(generate_key().expose_secret().to_hex()),
    )
    .unwrap();
    assert_eq!(&ciphertext[..5], *AESCRYPT_V3_HEADER);
}

#[test]
fn test_is_aescrypt_file_and_version() {
    let ciphertext = encrypt_to_vec(
        b"test",
        &FilePassword::new(generate_key().expose_secret().to_hex()),
    )
    .unwrap();
    assert!(is_aescrypt_file(&ciphertext));
    assert!(!is_aescrypt_file(b"not aes"));
    assert_eq!(aescrypt_version(&ciphertext), Some(3));
}

#[test]
fn test_ensure_v3_returns_error_on_invalid_legacy() {
    let legacy = vec![0x41, 0x45, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00];
    let result = ensure_v3(legacy, &FilePassword::new("wrong".to_owned()));
    assert!(result.is_err());
}

#[test]
fn test_ensure_v3_passes_through_v3_unchanged() {
    let v3 = encrypt_to_vec(
        b"v3",
        &FilePassword::new(generate_key().expose_secret().to_hex()),
    )
    .unwrap();
    let result = ensure_v3(v3.clone(), &FilePassword::new("any".to_owned())).unwrap();
    assert_eq!(v3, result);
}

#[test]
fn test_rotate_key_produces_different_ciphertext_and_new_key() {
    let plaintext = b"secret message";
    let old_key = generate_key();
    let old_password = FilePassword::new(old_key.expose_secret().to_hex());
    let original = encrypt_to_vec(plaintext, &old_password).unwrap();

    let (new_ciphertext, new_key) = rotate_key(&original, &old_password).unwrap();

    assert_ne!(original, new_ciphertext);
    assert_ne!(
        old_key.expose_secret().as_slice(),
        new_key.expose_secret().as_slice()
    );

    let decrypted = decrypt_to_vec(
        &new_ciphertext,
        &FilePassword::new(new_key.expose_secret().to_hex()),
    )
    .unwrap();
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

#[test]
fn test_decrypt_fails_with_wrong_password() {
    let plaintext = b"secret";
    let key1 = generate_key();
    let key2 = generate_key();

    let ciphertext =
        encrypt_to_vec(plaintext, &FilePassword::new(key1.expose_secret().to_hex())).unwrap();

    let wrong = decrypt_to_vec(
        &ciphertext,
        &FilePassword::new(key2.expose_secret().to_hex()),
    );
    assert!(wrong.is_err());
    assert!(matches!(wrong, Err(CoreError::Crypto(_))));
}
