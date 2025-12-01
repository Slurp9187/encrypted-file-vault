// tests/vector_tests.rs
mod support;
use support::{insert_test_file, TestDbPair};

use std::fs;
use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

use aescrypt_rs::aliases::Password;
use aescrypt_rs::convert::convert_to_v3;
use aescrypt_rs::{decrypt, encrypt};
use blake3::Hasher;
use chrono::Utc;
use encrypted_file_vault::aliases::{FileKey32, SecureConversionsExt, SecureRandomExt};
use serde::{Deserialize, Serialize};
use serde_json::json;

// Conditional tracing imports
#[cfg(feature = "logging")]
use tracing::{debug, info};

#[cfg(feature = "logging")]
use tracing_subscriber::EnvFilter;

fn init_tracing() {
    #[cfg(feature = "logging")]
    {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_test_writer()
                .with_env_filter(EnvFilter::from_default_env())
                .try_init();
        });
    }
    #[cfg(not(feature = "logging"))]
    {
        // no-op
    }
}

#[derive(Clone)]
struct ThreadSafeVec(Arc<Mutex<Vec<u8>>>);

impl Write for ThreadSafeVec {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct TestVector {
    plaintext: String,
    ciphertext_hex: String,
}

#[test]
fn upgrade_and_rotate_official_test_vectors() {
    init_tracing();

    #[cfg(feature = "logging")]
    info!("Starting official test vector upgrade & rotation test");

    let db = TestDbPair::new();

    #[cfg(feature = "logging")]
    info!("Using temporary DBs in {:?}", db.temp_dir());

    let output_dir = std::path::Path::new("tests/data/output");
    let _ = fs::remove_dir_all(output_dir);
    fs::create_dir_all(output_dir).unwrap();
    let log_path = output_dir.join("vector_upgrade_log.json");

    let versions = vec![
        ("v0", "tests/vector/data/test_vectors_v0.json"),
        ("v1", "tests/vector/data/test_vectors_v1.json"),
        ("v2", "tests/vector/data/test_vectors_v2.json"),
        ("v3", "tests/vector/data/test_vectors_v3.json"),
    ];

    let mut log_entries = Vec::new();
    let password = "Hello".to_owned();
    let iterations = 5;

    #[cfg(feature = "logging")]
    info!(
        "Processing {} vector versions with {} KDF iterations",
        versions.len(),
        iterations
    );

    for (version, json_path) in versions {
        #[cfg(feature = "logging")]
        info!("Loading {version} — {json_path}");

        let json_content = fs::read_to_string(json_path).expect("failed to read test vector file");
        let vectors: Vec<TestVector> =
            serde_json::from_str(&json_content).expect("invalid JSON in test vectors");

        #[cfg(feature = "logging")]
        info!("{version} — {} test vectors loaded", vectors.len());

        for (idx, vector) in vectors.iter().enumerate() {
            let ciphertext = hex::decode(&vector.ciphertext_hex).unwrap();

            let upgraded_v3 = if version != "v3" {
                #[cfg(feature = "logging")]
                debug!("{version} → v3 upgrade: test #{idx}");
                let buffer = Arc::new(Mutex::new(Vec::new()));
                let writer = ThreadSafeVec(buffer.clone());

                convert_to_v3(
                    Cursor::new(&ciphertext),
                    writer, // ← FIXED: removed the stray comma
                    &Password::new(password.clone()),
                    iterations,
                )
                .expect("v0/v1/v2 → v3 conversion failed");

                let _len_before = ciphertext.len();
                let data = {
                    let mut guard = buffer.lock().unwrap();
                    std::mem::take(&mut *guard)
                };
                let _len_after = data.len();

                #[cfg(feature = "logging")]
                info!("{version} test {idx:02}: upgraded {_len_before} → {_len_after} bytes");
                data
            } else {
                #[cfg(feature = "logging")]
                debug!("{version} test {idx:02}: already v3 — skipping upgrade");
                ciphertext
            };

            assert_eq!(&upgraded_v3[0..5], b"AES\x03\x00");

            let mut decrypted = Vec::new();
            decrypt(
                Cursor::new(&upgraded_v3),
                &mut decrypted,
                &Password::new(password.clone()),
            )
            .unwrap();
            assert_eq!(decrypted, vector.plaintext.as_bytes());

            let fresh_key: FileKey32 = FileKey32::random();
            let new_password = Password::new(fresh_key.expose_secret().to_hex());

            let output_file = output_dir.join(format!("{version}_test_{idx:02}.txt.aes"));
            let mut output = fs::File::create(&output_file).unwrap();

            #[cfg(feature = "logging")]
            debug!(
                "{version} test {idx:02}: rotating key → {}",
                output_file.display()
            );
            encrypt(
                Cursor::new(vector.plaintext.as_bytes()),
                &mut output,
                &new_password,
                iterations,
            )
            .unwrap();

            let mut hasher = Hasher::new();
            hasher.update(vector.plaintext.as_bytes());
            hasher.update(version.as_bytes());
            hasher.update(&idx.to_be_bytes());
            let file_id = hasher.finalize().to_hex().to_string();

            insert_test_file(
                &db,
                &format!("{version}_test_{idx:02}.txt"),
                vector.plaintext.len() as i64,
            );

            log_entries.push(json!({
                "version": version,
                "index": idx,
                "new_rotated_file": output_file.file_name().unwrap().to_string_lossy(),
                "new_password_hex": fresh_key.expose_secret().to_hex(),
                "file_id_blake3": file_id,
            }));
        }

        #[cfg(feature = "logging")]
        info!(
            "{version} — All {} vectors processed successfully",
            vectors.len()
        );
    }

    let log = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "total_vectors_processed": log_entries.len(),
        "entries": log_entries,
    });

    fs::write(&log_path, serde_json::to_string_pretty(&log).unwrap())
        .expect("failed to write vector log");

    #[cfg(feature = "logging")]
    info!(
        "Test vector upgrade + rotation completed — {} files processed",
        log_entries.len()
    );
    #[cfg(feature = "logging")]
    info!("Log written to {}", log_path.display());
}
