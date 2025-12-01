//! tests/db_tests.rs

mod common;
use common::{DbMode, TestDbPair};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use encrypted_file_vault::export::export_to_json;
use serde_json::Value;
use std::fs;

#[test]
fn full_lifecycle_export_contains_correct_password() {
    // Must be mutable because insert_test_file takes &mut self
    let mut db = TestDbPair::new(DbMode::Fresh);

    let export_path = db.path().join("export.json");

    let (file_id, key) = db.insert_test_file("Secret Document.pdf", 123_456);

    drop(db); // Close connections

    export_to_json(export_path.to_str().unwrap()).expect("export failed");

    let json_str = fs::read_to_string(&export_path).unwrap();
    let json: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(json["total_files"], 1);

    let file = &json["files"][0];
    assert_eq!(file["file_id"], file_id);
    assert_eq!(file["display_name"], "Secret Document.pdf");

    let decoded = URL_SAFE_NO_PAD
        .decode(file["password_base64url"].as_str().unwrap())
        .unwrap();
    assert_eq!(decoded, key.expose_secret().as_slice());
}
