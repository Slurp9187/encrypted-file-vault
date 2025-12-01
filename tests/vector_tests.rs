// tests/vector_tests.rs
mod common;
use common::{DbMode, TestDbPair};

// use aescrypt_rs::aliases::Password as AesCryptPassword; // only allowed here for legacy vectors
use aescrypt_rs::convert::convert_to_v3;
use aescrypt_rs::{decrypt, encrypt};
use blake3::Hasher;
use chrono::Utc;
use encrypted_file_vault::aliases::FilePassword;
use encrypted_file_vault::aliases::{FileKey32, SecureConversionsExt, SecureRandomExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

#[cfg(feature = "logging")]
use tracing::info;

fn init_tracing() {
    #[cfg(feature = "logging")]
    static INIT: std::sync::Once = std::sync::Once::new();
    #[cfg(feature = "logging")]
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();
    });
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
fn upgrade_and_rotate_vectors_both_modes() {
    init_tracing();

    let modes = if std::env::var("CI").is_ok()
        || std::env::var("GITHUB_ACTIONS").is_ok()
        || std::env::var("GITLAB_CI").is_ok()
        || std::env::var("CIRCLECI").is_ok()
    {
        vec![DbMode::Fresh]
    } else {
        vec![DbMode::Fresh, DbMode::Persistent]
    };

    for &mode in &modes {
        println!("=== Running vector test in {mode:?} mode ===");
        _run_vector_test(mode);
    }
}

fn _run_vector_test(mode: DbMode) {
    #[cfg(feature = "logging")]
    info!("Starting vector test — mode: {mode:?}");

    let mut db = TestDbPair::new(mode);

    let output_dir = db.path().join("output");
    let _ = fs::remove_dir_all(&output_dir);
    fs::create_dir_all(&output_dir).unwrap();
    let log_path = output_dir.join(format!("vector_log_{mode:?}.json"));

    let versions = [
        ("v0", "tests/vector/data/test_vectors_v0.json"),
        ("v1", "tests/vector/data/test_vectors_v1.json"),
        ("v2", "tests/vector/data/test_vectors_v2.json"),
        ("v3", "tests/vector/data/test_vectors_v3.json"),
    ];

    let mut log_entries = Vec::new();
    let legacy_password_str = "Hello".to_owned();
    let iterations = 5;

    for (version, path) in versions {
        let content = fs::read_to_string(path).expect("read vector file");
        let vectors: Vec<TestVector> = serde_json::from_str(&content).expect("parse vectors");

        for (idx, vec) in vectors.iter().enumerate() {
            let ciphertext = hex::decode(&vec.ciphertext_hex).unwrap();

            // Legacy → v3 upgrade path
            let v3_data = if version != "v3" {
                let buffer = Arc::new(Mutex::new(Vec::new()));
                {
                    let writer = ThreadSafeVec(buffer.clone());
                    let legacy_password = FilePassword::new(legacy_password_str.clone());
                    convert_to_v3(
                        Cursor::new(&ciphertext),
                        writer,
                        &legacy_password,
                        iterations,
                    )
                    .expect("convert_to_v3 failed");
                }
                Arc::try_unwrap(buffer)
                    .expect("buffer still has references")
                    .into_inner()
                    .expect("mutex poisoned")
            } else {
                ciphertext
            };

            assert_eq!(&v3_data[0..5], b"AES\x03\x00");

            // Verify we can decrypt with the original legacy password
            let mut decrypted = Vec::new();
            decrypt(
                Cursor::new(&v3_data),
                &mut decrypted,
                &FilePassword::new(legacy_password_str.clone()),
            )
            .unwrap();
            assert_eq!(decrypted, vec.plaintext.as_bytes());

            // Modern workflow: use random FileKey32
            let new_key = FileKey32::random();
            let new_password = FilePassword::new(new_key.expose_secret().to_hex());

            let out_file = output_dir.join(format!("{version}_test_{idx:02}.txt.aes"));
            let mut f = fs::File::create(&out_file).unwrap();
            encrypt(
                Cursor::new(vec.plaintext.as_bytes()),
                &mut f,
                &new_password,
                iterations,
            )
            .unwrap();

            // Deterministic file_id for logging
            let mut hasher = Hasher::new();
            hasher.update(vec.plaintext.as_bytes());
            hasher.update(version.as_bytes());
            hasher.update(&idx.to_be_bytes());
            let file_id = hasher.finalize().to_hex().to_string();

            db.insert_test_file(
                &format!("{version}_test_{idx:02}.txt"),
                vec.plaintext.len() as i64,
            );

            log_entries.push(json!({
                "version": version,
                "index": idx,
                "file": out_file.file_name().unwrap().to_string_lossy(),
                "new_password_hex": new_key.expose_secret().to_hex(),
                "file_id": file_id,
            }));
        }
    }

    let log = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "mode": format!("{mode:?}"),
        "total": log_entries.len(),
        "entries": log_entries
    });

    fs::write(&log_path, serde_json::to_string_pretty(&log).unwrap()).unwrap();

    #[cfg(feature = "logging")]
    info!(
        "Vector test complete ({mode:?}) — {} files → {}",
        log_entries.len(),
        log_path.display()
    );
}
