// tests/core_tests.rs
//! Final working test suite — professional tracing logs (optional)

use std::fs;

use aescrypt_rs::aliases::Password;
use aescrypt_rs::decrypt;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tempfile::tempdir;

// Conditional tracing imports
#[cfg(feature = "logging")]
use tracing::{debug, info};

#[cfg(feature = "logging")]
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

// Bring the secure conversion trait into scope unconditionally
// This is required for .to_hex() on FileKey32 secrets
use encrypted_file_vault::aliases::{FileKey32, SecureConversionsExt};

use encrypted_file_vault::consts::{
    AESCRYPT_V3_HEADER, DEFAULT_FILENAME_STYLE, DEFAULT_ID_LENGTH_HEX,
};
use encrypted_file_vault::core::*;
use encrypted_file_vault::error::CoreError;
use encrypted_file_vault::{index, vault};

/// Initialize tracing only when logging feature is enabled
fn init_tracing() {
    #[cfg(feature = "logging")]
    {
        let _ = tracing_subscriber::registry()
            .with(fmt::layer().with_test_writer())
            .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
            .try_init();
    }
    #[cfg(not(feature = "logging"))]
    {
        // no-op
    }
}

#[test]
fn test_generate_key_is_random_and_32_bytes() {
    init_tracing();
    let key1 = generate_key();
    let key2 = generate_key();
    assert_eq!(key1.expose_secret().len(), 32);
    assert_ne!(
        key1.expose_secret().as_slice(),
        key2.expose_secret().as_slice()
    );
}

#[test]
fn test_blake3_hex_is_64_chars_lowercase() {
    init_tracing();

    #[cfg(feature = "logging")]
    info!("Running blake3_hex test — fast but involves hashing");

    let hex = blake3_hex(b"hello world");
    assert_eq!(hex.len(), 64);
    assert!(hex
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
}

#[test]
fn test_encrypt_decrypt_roundtrip_in_memory() {
    init_tracing();

    let plaintext = b"Attack at dawn!";
    let key = generate_key();
    let password = Password::new(key.expose_secret().to_hex());

    let ciphertext = encrypt_to_vec(plaintext, &password).unwrap();
    let decrypted = decrypt_to_vec(&ciphertext, &password).unwrap();

    assert!(ciphertext.starts_with(b"AES"));
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

#[test]
fn test_encrypt_to_vec_produces_v3_header() {
    init_tracing();
    let ciphertext = encrypt_to_vec(
        b"small",
        &Password::new(generate_key().expose_secret().to_hex()),
    )
    .unwrap();
    assert_eq!(&ciphertext[..5], *AESCRYPT_V3_HEADER);
}

#[test]
fn test_is_aescrypt_file_and_version() {
    init_tracing();

    #[cfg(feature = "logging")]
    info!("[fast] Verifying AES-Crypt file magic detection and version parsing");

    let ciphertext = encrypt_to_vec(
        b"test",
        &Password::new(generate_key().expose_secret().to_hex()),
    )
    .unwrap();

    assert!(is_aescrypt_file(&ciphertext));
    assert_eq!(aescrypt_version(&ciphertext), Some(3));

    assert!(!is_aescrypt_file(b"not aes"));
    assert_eq!(aescrypt_version(b"AES"), None);
}

#[test]
fn test_ensure_v3_returns_error_on_invalid_legacy() {
    init_tracing();
    let legacy = vec![0x41, 0x45, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00];
    let result = ensure_v3(legacy, &Password::new("wrong".to_owned()));
    assert!(result.is_err());
}

#[test]
fn test_ensure_v3_passes_through_v3_unchanged() {
    init_tracing();
    let v3 = encrypt_to_vec(
        b"v3",
        &Password::new(generate_key().expose_secret().to_hex()),
    )
    .unwrap();
    let result = ensure_v3(v3.clone(), &Password::new("any".to_owned())).unwrap();
    assert_eq!(v3, result);
}

#[test]
fn test_rotate_key_produces_different_ciphertext_and_new_key() {
    init_tracing();

    #[cfg(feature = "logging")]
    info!("Starting key rotation test — this one can be slow");

    let plaintext = b"secret message";
    let old_key = generate_key();

    #[cfg(feature = "logging")]
    debug!("Generated old key: {}", old_key.expose_secret().to_hex());

    let old_password = Password::new(old_key.expose_secret().to_hex());
    let original = encrypt_to_vec(plaintext, &old_password).unwrap();

    #[cfg(feature = "logging")]
    info!("Encrypting with old key...");

    let (new_ciphertext, new_key) = rotate_key(&original, &old_password).unwrap();

    #[cfg(feature = "logging")]
    info!(
        "Successfully rotated to new key: {}",
        new_key.expose_secret().to_hex()
    );

    assert_ne!(original, new_ciphertext);
    assert_ne!(
        old_key.expose_secret().as_slice(),
        new_key.expose_secret().as_slice()
    );

    let decrypted = decrypt_to_vec(
        &new_ciphertext,
        &Password::new(new_key.expose_secret().to_hex()),
    )
    .unwrap();
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());

    #[cfg(feature = "logging")]
    info!("Key rotation test completed successfully");
}

#[test]
fn test_encrypt_file_and_decrypt_file_roundtrip() {
    init_tracing();

    let dir = tempdir().unwrap();
    let plain = dir.path().join("plain.txt");
    let enc = dir.path().join("secret.aes");
    let dec = dir.path().join("out.txt");

    fs::write(&plain, b"The quick brown fox jumps over the lazy dog").unwrap();

    let password = Password::new(generate_key().expose_secret().to_hex());

    let size1 = encrypt_file(&plain, &enc, &password).unwrap();
    let size2 = decrypt_file(&enc, &dec, &password).unwrap();

    assert_eq!(size1, size2);
    assert_eq!(fs::read(&dec).unwrap(), fs::read(&plain).unwrap());
}

#[test]
fn test_add_file_creates_valid_entry_and_stores_key() {
    init_tracing();

    #[cfg(feature = "logging")]
    {
        info!("[SLOW] test_add_file_creates_valid_entry_and_stores_key — this test performs:");
        info!("       • Real file I/O (write fake pdf)");
        info!("       • Full AES-Crypt v3 encryption with 600_000 KDF iterations");
        info!("       • Two SQLCipher DB writes (vault + index)");
        info!("       • Expected runtime: 30–90 seconds on normal hardware");
        info!("       → This is intentional and correct!");
    }

    let dir = tempdir().unwrap();
    let plain_path = dir.path().join("doc.pdf");
    let enc_path = dir.path().join("doc.pdf.aes");
    fs::write(&plain_path, b"fake pdf content").unwrap();

    std::env::set_var("EFV_VAULT_KEY", "test-vault");
    std::env::set_var("EFV_INDEX_KEY", "test-index");

    let vault_conn = vault::open_vault_db().unwrap();
    let index_conn = index::open_index_db().unwrap();

    let entry = add_file(&plain_path, &enc_path, &vault_conn, &index_conn, None, None).unwrap();

    assert!(enc_path.exists());
    assert_eq!(entry.display_name, "doc.pdf");
    assert_eq!(entry.plaintext_size, 16);
    assert!(!entry.file_id.is_empty());

    let stored: Vec<u8> = vault_conn
        .query_row(
            "SELECT password_blob FROM keys WHERE file_id = ?1",
            [&entry.file_id],
            |r| r.get(0),
        )
        .unwrap();

    assert_eq!(stored.len(), 32);

    let mut output = Vec::new();
    decrypt(
        std::io::Cursor::new(fs::read(&enc_path).unwrap()),
        &mut output,
        &Password::new(hex::encode(&stored)),
    )
    .unwrap();
    assert_eq!(output, b"fake pdf content");

    #[cfg(feature = "logging")]
    info!("[SLOW] test_add_file_creates_valid_entry_and_stores_key completed successfully");
}

#[test]
fn test_password_representations_are_correct_and_consistent() {
    init_tracing();

    let key = FileKey32::new([0x42; 32]);
    let repr = password_representations(&key);

    assert_eq!(
        repr.hex,
        "4242424242424242424242424242424242424242424242424242424242424242"
    );
    assert_eq!(repr.base64, "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=");
    assert_eq!(
        repr.base64url_no_pad,
        "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"
    );

    assert_eq!(repr.hex, key.expose_secret().to_hex());
    assert_eq!(repr.base64, STANDARD.encode(key.expose_secret()));
}

#[test]
fn test_store_and_retrieve_key_blob_via_db() {
    init_tracing();

    let _dir = tempdir().unwrap();
    std::env::set_var("EFV_VAULT_KEY", "test");

    let conn = vault::open_vault_db().unwrap();
    let key = generate_key();
    let file_id = "myfile123";

    store_key_blob(&conn, file_id, &key).unwrap();

    let retrieved: Vec<u8> = conn
        .query_row(
            "SELECT password_blob FROM keys WHERE file_id = ?1",
            [file_id],
            |r| r.get(0),
        )
        .unwrap();

    assert_eq!(retrieved, key.expose_secret().as_slice());
}

#[test]
fn test_add_file_uses_defaults_when_options_none() {
    init_tracing();

    let dir = tempdir().unwrap();
    let plain = dir.path().join("note.txt");
    fs::write(&plain, b"hello").unwrap();

    std::env::set_var("EFV_VAULT_KEY", "x");
    std::env::set_var("EFV_INDEX_KEY", "y");

    let vault_conn = vault::open_vault_db().unwrap();
    let index_conn = index::open_index_db().unwrap();

    let entry = add_file(
        &plain,
        &dir.path().join("note.txt.aes"),
        &vault_conn,
        &index_conn,
        None,
        None,
    )
    .unwrap();

    assert_eq!(entry.filename_style, DEFAULT_FILENAME_STYLE);
    assert_eq!(entry.id_length_hex, DEFAULT_ID_LENGTH_HEX as u64);
}

#[test]
fn test_decrypt_fails_with_wrong_password() {
    init_tracing();

    let plaintext = b"secret";
    let key1 = generate_key();
    let key2 = generate_key();

    let ciphertext =
        encrypt_to_vec(plaintext, &Password::new(key1.expose_secret().to_hex())).unwrap();
    let wrong = decrypt_to_vec(&ciphertext, &Password::new(key2.expose_secret().to_hex()));

    assert!(wrong.is_err());
    assert!(matches!(wrong, Err(CoreError::Crypto(_))));
}
