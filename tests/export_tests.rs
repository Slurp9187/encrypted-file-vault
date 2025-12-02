//! tests/export_tests.rs
//! Comprehensive tests for export functionality

mod common;
use common::{DbMode, TestDbPair};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use encrypted_file_vault::export::json::export_to_json;
use serde_json::Value;
use serial_test::serial; // ← This is the only thing you need
use std::fs;
use tempfile::tempdir;

#[test]
#[serial]
fn export_contains_correct_password_and_metadata() {
    let mut db = TestDbPair::new(DbMode::Fresh);

    let (file_id, key) = db.insert_test_file("My Resume.docx", 987_654);

    let export_dir = tempdir().unwrap();
    let export_path = export_dir.path().join("vault-export.json");

    drop(db);

    export_to_json(export_path.to_str().unwrap()).expect("export failed");

    let json_str = fs::read_to_string(&export_path).unwrap();
    let json: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(json["total_files"], 1);
    assert_eq!(json["export_format"], "encrypted-file-vault-v1");
    // Fixed: works whether milliseconds are present or not
    assert!(json["exported_at"].as_str().unwrap().contains('Z'));

    let file = &json["files"][0];
    assert_eq!(file["file_id"], file_id);
    assert_eq!(file["display_name"], "My Resume.docx");

    let decoded = URL_SAFE_NO_PAD
        .decode(file["password_base64url"].as_str().unwrap())
        .unwrap();
    assert_eq!(decoded, key.expose_secret().as_slice());
}

#[test]
#[serial] // ← Same here — no racing
fn export_multiple_files_all_correct() {
    let mut db = TestDbPair::new(DbMode::Fresh);

    let (id1, key1) = db.insert_test_file("Taxes 2024.pdf", 2_100_000);
    let (id2, key2) = db.insert_test_file("Love Letter.txt", 420);
    let (id3, key3) = db.insert_test_file("Photo.jpg", 15_000_000);

    let export_dir = tempdir().unwrap();
    let export_path = export_dir.path().join("full-vault.json");

    drop(db);

    export_to_json(export_path.to_str().unwrap()).expect("export failed");

    let json_str = fs::read_to_string(&export_path).unwrap();
    let json: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(json["total_files"], 3);

    let files = json["files"].as_array().unwrap();

    let find_file = |name: &str| {
        files
            .iter()
            .find(|f| f["display_name"] == name)
            .unwrap_or_else(|| panic!("File not found: {name}"))
    };

    let taxes = find_file("Taxes 2024.pdf");
    assert_eq!(taxes["file_id"], id1);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(taxes["password_base64url"].as_str().unwrap())
            .unwrap(),
        key1.expose_secret().as_slice()
    );

    let love = find_file("Love Letter.txt");
    assert_eq!(love["file_id"], id2);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(love["password_base64url"].as_str().unwrap())
            .unwrap(),
        key2.expose_secret().as_slice()
    );

    let photo = find_file("Photo.jpg");
    assert_eq!(photo["file_id"], id3);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(photo["password_base64url"].as_str().unwrap())
            .unwrap(),
        key3.expose_secret().as_slice()
    );

    let names: Vec<&str> = files
        .iter()
        .map(|f| f["display_name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["Love Letter.txt", "Photo.jpg", "Taxes 2024.pdf"]
    );
}
