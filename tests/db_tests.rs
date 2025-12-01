// tests/db_tests.rs
//! Integration tests for export functionality using real databases

mod support;
use support::{insert_test_file, DbMode, TestDbPair}; // ← added DbMode import

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use encrypted_file_vault::export::export_to_json;
use serde_json::Value;
use std::fs;

#[cfg(feature = "logging")]
use tracing::info;

#[test]
fn full_lifecycle_export_contains_correct_password() {
    // Explicitly use fresh DBs — keeps CI fast and deterministic
    let db = TestDbPair::new(DbMode::Fresh);

    #[cfg(feature = "logging")]
    info!(
        "Created vault + index databases in {:?} (Fresh mode)",
        db.path()
    );

    // Insert a fake file
    let (file_id, key) = insert_test_file(&db, "Secret Document.pdf", 123_456);

    // Export everything
    let export_path = db.path().join("export.json");
    export_to_json(export_path.to_str().unwrap()).expect("export_to_json failed");

    #[cfg(feature = "logging")]
    info!("Export written to {}", export_path.display());

    // Read it back and verify
    let json_str = fs::read_to_string(&export_path).expect("read export.json");
    let json: Value = serde_json::from_str(&json_str).expect("valid JSON");

    assert_eq!(json["total_files"], 1);
    assert!(json["warning"].as_str().unwrap().contains("PLAINTEXT"));

    let file = &json["files"][0];
    assert_eq!(file["file_id"], file_id);
    assert_eq!(file["display_name"], "Secret Document.pdf");

    let exported_b64 = file["password_base64url"].as_str().unwrap();
    let decoded = URL_SAFE_NO_PAD
        .decode(exported_b64)
        .expect("valid base64url");
    assert_eq!(decoded, key.expose_secret().as_slice());

    #[cfg(feature = "logging")]
    info!("Export test passed — password round-trips correctly!");
}
