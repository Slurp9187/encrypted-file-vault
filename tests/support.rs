// tests/support.rs
//! Test utilities for encrypted-file-vault integration tests
//! Now with PERSISTENT mode for decrypt_batch development

use encrypted_file_vault::aliases::{FileKey32, SecureConversionsExt, SecureRandomExt};
use encrypted_file_vault::{index::open_index_db, vault::open_vault_db};
use rusqlite::{params, Connection};
use std::env;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tracing::{debug, info};

pub fn init_test_logging() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();
    });
}

pub struct TestDbPair {
    _temp_dir: Option<TempDir>,        // None = persistent mode
    _persistent_path: Option<PathBuf>, // For temp_dir() in persistent mode
    pub vault: Connection,
    pub index: Connection,
    _env_guard: EnvGuard,
}

struct EnvGuard {
    old_home: Option<String>,
    old_profile: Option<String>,
    old_vault_key: Option<String>,
    old_index_key: Option<String>,
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(v) = &self.old_home {
            env::set_var("HOME", v);
        } else {
            env::remove_var("HOME");
        }
        if let Some(v) = &self.old_profile {
            env::set_var("USERPROFILE", v);
        } else {
            env::remove_var("USERPROFILE");
        }
        if let Some(v) = &self.old_vault_key {
            env::set_var("EFV_VAULT_KEY", v);
        } else {
            env::remove_var("EFV_VAULT_KEY");
        }
        if let Some(v) = &self.old_index_key {
            env::set_var("EFV_INDEX_KEY", v);
        } else {
            env::remove_var("EFV_INDEX_KEY");
        }
        debug!("TestDbPair dropped — original environment restored");
    }
}

impl TestDbPair {
    /// Fresh, isolated DBs — default for all tests
    pub fn new() -> Self {
        Self::new_internal(true)
    }

    /// PERSISTENT DBs — kept across test runs in ./test_persistent_dbs/
    #[allow(dead_code)]
    pub fn persistent() -> Self {
        info!("PERSISTENT TestDbPair — using ./test_persistent_dbs/");
        Self::new_internal(false)
    }

    fn new_internal(ephemeral: bool) -> Self {
        init_test_logging();

        let (temp_dir, persistent_path) = if ephemeral {
            let temp = TempDir::new().expect("Failed to create temp dir");
            info!("Created ephemeral test directory: {:?}", temp.path());
            (Some(temp), None)
        } else {
            let path = PathBuf::from("./test_persistent_dbs");
            std::fs::create_dir_all(&path).ok();
            info!("Using persistent test directory: {:?}", path);
            (None, Some(path))
        };

        let old_home = env::var("HOME").ok();
        let old_profile = env::var("USERPROFILE").ok();
        let old_vault_key = env::var("EFV_VAULT_KEY").ok();
        let old_index_key = env::var("EFV_INDEX_KEY").ok();

        let root_path: PathBuf = persistent_path
            .clone()
            .or_else(|| temp_dir.as_ref().map(|t| t.path().to_owned()))
            .unwrap();

        env::set_var("HOME", root_path.to_str().unwrap());
        env::set_var("USERPROFILE", root_path.to_str().unwrap());
        env::set_var("EFV_VAULT_KEY", "test-vault-secret-123");
        env::set_var("EFV_INDEX_KEY", "test-index-secret-456");

        debug!("Environment overridden for test isolation");

        let env_guard = EnvGuard {
            old_home,
            old_profile,
            old_vault_key,
            old_index_key,
        };

        let vault = open_vault_db().expect("Failed to open vault DB");
        let index = open_index_db().expect("Failed to open index DB");

        if ephemeral {
            vault.execute("DELETE FROM keys;", params![]).unwrap();
            index.execute("DELETE FROM files;", params![]).unwrap();
            debug!("Cleared existing data from vault and index databases");
        } else {
            info!("Persistent mode — keeping existing data in ./test_persistent_dbs/");
        }

        info!(
            "TestDbPair ready — {} mode",
            if ephemeral { "ephemeral" } else { "PERSISTENT" }
        );

        Self {
            _temp_dir: temp_dir,
            _persistent_path: persistent_path,
            vault,
            index,
            _env_guard: env_guard,
        }
    }

    #[allow(dead_code)]
    pub fn temp_dir(&self) -> &Path {
        self._temp_dir
            .as_ref()
            .map(|t| t.path())
            .or(self._persistent_path.as_deref())
            .unwrap_or_else(|| Path::new("./test_persistent_dbs"))
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

    debug!("Inserting test file: \"{display_name}\" (size: {plaintext_size} bytes)");
    debug!("Generated file key: {}", key.expose_secret().to_hex());
    debug!("Derived file_id: {file_id}");

    db.vault
        .execute(
            "INSERT INTO keys (file_id, password_blob, created_at) VALUES (?1, ?2, datetime('now'))",
            params![file_id, key.expose_secret() as &[u8]],
        )
        .expect("failed to insert key into vault DB");

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
        .expect("failed to insert file metadata");

    info!("Test file inserted — file_id = {file_id}");

    (file_id, key)
}
