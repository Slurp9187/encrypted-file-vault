// tests/support.rs
//! Test utilities — isolated databases for every test

use encrypted_file_vault::aliases::{FileKey32, SecureRandomExt};
use encrypted_file_vault::{index::open_index_db, vault::open_vault_db};
use rusqlite::{params, Connection};
use std::env;
use std::path::Path;
use tempfile::TempDir;

/// Fresh, isolated vault + index databases for every test
pub struct TestDbPair {
    /// Keeps the temporary directory alive for the lifetime of the test
    _temp_dir: TempDir,
    /// Vault database connection (SQLCipher)
    pub vault: Connection,
    /// Index database connection (SQLCipher)
    pub index: Connection,
}

impl TestDbPair {
    pub fn new() -> Self {
        let temp_dir = TempDir::new().expect("failed to create temp dir");

        env::set_var("EFV_TEST_MODE", "1");
        env::set_var(
            "EFV_VAULT_DB",
            temp_dir.path().join("vault.db").to_str().unwrap(),
        );
        env::set_var(
            "EFV_INDEX_DB",
            temp_dir.path().join("index.db").to_str().unwrap(),
        );
        env::set_var("EFV_VAULT_KEY", "test-vault-secret");
        env::set_var("EFV_INDEX_KEY", "test-index-secret");

        let vault = open_vault_db().expect("failed to open vault db");
        let index = open_index_db().expect("failed to open index db");

        Self {
            _temp_dir: temp_dir,
            vault,
            index,
        }
    }

    /// Returns the temporary directory path — used by all tests
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        self._temp_dir.path()
    }
}

impl Default for TestDbPair {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper used by integration tests
#[allow(dead_code)]
pub fn insert_test_file(
    db: &TestDbPair,
    display_name: &str,
    plaintext_size: i64,
) -> (String, FileKey32) {
    let key = FileKey32::random();
    let file_id = blake3::hash(key.expose_secret()).to_hex().to_string();

    db.vault
        .execute(
            "INSERT INTO keys (file_id, password_blob, created_at) VALUES (?1, ?2, datetime('now'))",
            params![file_id, key.expose_secret() as &[u8]],
        )
        .expect("failed to insert key");

    db.index
        .execute(
            r#"INSERT INTO files (
                file_id, content_hash, display_name, current_path,
                plaintext_size, created_at, filename_style, id_length
            ) VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'), ?6, ?7)"#,
            params![
                &file_id,
                &file_id,
                display_name,
                format!("/fake/{}.enc", display_name),
                plaintext_size,
                "human",
                64i64
            ],
        )
        .expect("failed to insert file metadata");

    (file_id, key)
}
