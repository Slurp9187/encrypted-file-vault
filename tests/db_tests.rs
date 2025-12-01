// tests/db_tests.rs
mod support;
use secure_gate::SecureConversionsExt;
use support::{insert_test_file, TestDbPair};

use encrypted_file_vault::export::export_to_json;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use std::fs;

// Add tracing
use tracing::{debug, info};

#[test]
fn full_lifecycle_export_contains_correct_password() {
    // Initialize tracing once
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    info!("Starting full_lifecycle_export_contains_correct_password integration test");

    let db = TestDbPair::new();
    info!(
        "Created temporary vault + index databases in {:?}",
        db.temp_dir()
    );

    let (file_id, key) = insert_test_file(&db, "Secret Document.pdf", 123_456);
    debug!("Inserted test file — file_id = {file_id}");
    debug!("Generated file key (hex): {}", key.expose_secret().to_hex());

    let export_path = db.temp_dir().join("export.json");
    info!("Exporting vault to {}", export_path.display());

    export_to_json(export_path.to_str().unwrap()).expect("export_to_json failed");

    info!("Export completed — reading JSON back");
    let json_str = fs::read_to_string(&export_path).expect("failed to read export.json");
    let json: Value = serde_json::from_str(&json_str).expect("invalid JSON in export");

    info!(
        "Export contains {} file(s)",
        json["total_files"].as_u64().unwrap()
    );
    assert_eq!(json["total_files"], 1);
    assert!(json["warning"].as_str().unwrap().contains("PLAINTEXT"));

    let file = &json["files"][0];
    assert_eq!(file["file_id"], file_id);
    assert_eq!(file["display_name"], "Secret Document.pdf");

    let exported_b64 = file["password_base64url"].as_str().unwrap();
    let decoded = URL_SAFE_NO_PAD
        .decode(exported_b64)
        .expect("invalid base64url");

    debug!("Decoded exported password matches original key");
    assert_eq!(decoded, key.expose_secret());

    info!("Integration test passed: export works perfectly!");
}
