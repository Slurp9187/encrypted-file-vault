// tests/support.rs
#[cfg(feature = "logging")]
use encrypted_file_vault::aliases::SecureConversionsExt;
use encrypted_file_vault::aliases::{FileKey32, SecureRandomExt};
use encrypted_file_vault::{index::open_index_db, vault::open_vault_db};
use rusqlite::{params, Connection};
use std::env;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[cfg(feature = "logging")]
use tracing::{debug, info};
#[cfg(feature = "logging")]
use tracing_subscriber::EnvFilter;

pub fn init_test_logging() {
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
}

pub struct TestDbPair {
    temp_dir: TempDir,
    pub vault: Connection,
    pub index: Connection,
}

impl TestDbPair {
    pub fn new() -> Self {
        init_test_logging();

        let temp_dir = TempDir::new().expect("failed to create temp dir");

        // Force test mode + unique DB paths
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

        let vault = open_vault_db().expect("open vault db");
        let index = open_index_db().expect("open index db");

        Self {
            temp_dir,
            vault,
            index,
        }
    }

    pub fn temp_dir(&self) -> &Path {
        self.temp_dir.path()
    }
}

impl Default for TestDbPair {
    fn default() -> Self {
        Self::new()
    }
}

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
        .expect("insert key");

    db.index
        .execute(
            r#"
            INSERT INTO files (
                file_id, content_hash, display_name, current_path,
                plaintext_size, created_at, filename_style, id_length
            ) VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'), ?6, ?7)
            "#,
            params![
                &file_id,
                &file_id,
                display_name,
                format!("/fake/{}.enc", display_name),
                plaintext_size,
                "human",
                64i64,
            ],
        )
        .expect("insert file");

    (file_id, key)
}
