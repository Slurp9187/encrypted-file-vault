// tests/db_tests.rs
//! Integration tests for export functionality using real databases

mod support;
use support::{insert_test_file, TestDbPair};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use encrypted_file_vault::export::export_to_json;
use serde_json::Value;
use std::fs;

// Import the `info!` macro from tracing (used when RUST_LOG=info)
#[cfg(feature = "logging")]
use tracing::info;

#[test]
fn full_lifecycle_export_contains_correct_password() {
    // Fresh, isolated databases for this test
    let db = TestDbPair::new();

    // Only print when logging is enabled
    #[cfg(feature = "logging")]
    info!(
        "Created temporary vault + index databases in {:?}",
        db.path()
    );

    // Insert a fake file into both databases
    let (file_id, key) = insert_test_file(&db, "Secret Document.pdf", 123_456);

    // Export everything to JSON
    let export_path = db.path().join("export.json");
    export_to_json(export_path.to_str().unwrap()).expect("export_to_json failed");

    #[cfg(feature = "logging")]
    info!("Export completed — reading JSON back");

    // Read the exported file
    let json_str = fs::read_to_string(&export_path).expect("failed to read export.json");
    let json: Value = serde_json::from_str(&json_str).expect("invalid JSON in export");

    // Basic checks
    assert_eq!(json["total_files"], 1);
    assert!(json["warning"].as_str().unwrap().contains("PLAINTEXT"));

    let file = &json["files"][0];
    assert_eq!(file["file_id"], file_id);
    assert_eq!(file["display_name"], "Secret Document.pdf");

    // The password must match exactly what we inserted
    let exported_b64 = file["password_base64url"].as_str().unwrap();
    let decoded = URL_SAFE_NO_PAD
        .decode(exported_b64)
        .expect("invalid base64url in export");

    assert_eq!(decoded, key.expose_secret().as_slice());

    #[cfg(feature = "logging")]
    info!("Integration test passed: export contains correct password!");
}
