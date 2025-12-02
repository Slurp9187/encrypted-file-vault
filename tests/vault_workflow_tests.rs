// tests/core/vault_workflow.rs
mod common;
use aescrypt_rs::decrypt;
use common::DbMode;
use common::TestDbPair;
use encrypted_file_vault::add_file;
use encrypted_file_vault::aliases::FilePassword;
use encrypted_file_vault::consts::{DEFAULT_FILENAME_STYLE, DEFAULT_ID_LENGTH_HEX};
use encrypted_file_vault::key_ops::generate_key;
use encrypted_file_vault::vault_db_ops::store_key_blob;
use serial_test::serial;
use std::fs;
use tempfile::tempdir;

#[test]
#[serial]
fn test_add_file_creates_valid_entry_and_stores_key() {
    let mut db = TestDbPair::new(DbMode::Fresh);

    let dir = tempdir().unwrap();
    let plain_path = dir.path().join("doc.pdf");
    let enc_path = dir.path().join("doc.pdf.aes");
    fs::write(&plain_path, b"fake pdf content").unwrap();

    let entry = add_file(&plain_path, &enc_path, &mut db.vault, &db.index, None, None).unwrap();

    assert!(enc_path.exists());
    assert_eq!(entry.display_name, "doc.pdf");
    assert_eq!(entry.plaintext_size, 16);
    assert!(!entry.file_id.is_empty());

    let stored: Vec<u8> = db
        .vault
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
        &FilePassword::new(hex::encode(&stored)),
    )
    .unwrap();
    assert_eq!(output, b"fake pdf content");
}

#[test]
#[serial]
fn test_store_and_retrieve_key_blob_via_db() {
    let mut db = TestDbPair::new(DbMode::Fresh);

    let key = generate_key();
    let file_id = "myfile123";

    store_key_blob(&mut db.vault, file_id, &key).unwrap();

    let retrieved: Vec<u8> = db
        .vault
        .query_row(
            "SELECT password_blob FROM keys WHERE file_id = ?1",
            [file_id],
            |r| r.get(0),
        )
        .unwrap();

    assert_eq!(retrieved, key.expose_secret().as_slice());
}

#[test]
#[serial]
fn test_add_file_uses_defaults_when_options_none() {
    let mut db = TestDbPair::new(DbMode::Fresh);

    let dir = tempdir().unwrap();
    let plain = dir.path().join("note.txt");
    fs::write(&plain, b"hello").unwrap();

    let entry = add_file(
        &plain,
        &dir.path().join("note.txt.aes"),
        &mut db.vault,
        &db.index,
        None,
        None,
    )
    .unwrap();

    assert_eq!(entry.filename_style, DEFAULT_FILENAME_STYLE);
    assert_eq!(entry.id_length_hex, DEFAULT_ID_LENGTH_HEX as u64);
}
