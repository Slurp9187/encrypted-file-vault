// tests/support.rs
//! Test utilities — fresh vs persistent database modes

use encrypted_file_vault::aliases::{FileKey32, SecureRandomExt};
use encrypted_file_vault::{index::open_index_db, vault::open_vault_db};
use rusqlite::{params, Connection};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbMode {
    Fresh,
    Persistent,
}

pub struct TestDbPair {
    pub vault: Connection,
    pub index: Connection,
    pub mode: DbMode,
    pub base_path: PathBuf,
}

impl TestDbPair {
    pub fn new(mode: DbMode) -> Self {
        let base = PathBuf::from("tests/data");
        fs::create_dir_all(&base).expect("failed to create tests/data");

        let (index_name, vault_name) = match mode {
            DbMode::Fresh => ("index_fresh.db", "vault_fresh.db"),
            DbMode::Persistent => ("index_persistent.db", "vault_persistent.db"),
        };

        let index_path = base.join(index_name);
        let vault_path = base.join(vault_name);

        // Always delete fresh DBs → truly clean start
        if mode == DbMode::Fresh {
            let _ = fs::remove_file(&index_path);
            let _ = fs::remove_file(&vault_path);
        }

        env::set_var("EFV_TEST_MODE", "1");
        env::set_var("EFV_VAULT_DB", vault_path.to_str().unwrap());
        env::set_var("EFV_INDEX_DB", index_path.to_str().unwrap());
        env::set_var("EFV_VAULT_KEY", "test-vault-secret-2025");
        env::set_var("EFV_INDEX_KEY", "test-index-secret-2025");

        let vault = open_vault_db().expect("open vault db");
        let index = open_index_db().expect("open index db");

        Self {
            vault,
            index,
            mode,
            base_path: base,
        }
    }

    pub fn path(&self) -> &Path {
        &self.base_path
    }

    /// Convenience method used by vector & export tests
    pub fn insert_test_file(&self, display_name: &str, plaintext_size: i64) -> (String, FileKey32) {
        let key = FileKey32::random();
        let file_id = blake3::hash(key.expose_secret()).to_hex().to_string();

        self.vault
            .execute(
                "INSERT INTO keys (file_id, password_blob, created_at) VALUES (?1, ?2, datetime('now'))",
                params![file_id, key.expose_secret() as &[u8]],
            )
            .expect("insert key");

        self.index
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
                    64i64,
                ],
            )
            .expect("insert file metadata");

        (file_id, key)
    }
}

impl Default for TestDbPair {
    fn default() -> Self {
        Self::new(DbMode::Fresh)
    }
}

// Legacy free function — kept for minimal changes in other tests
pub fn insert_test_file(
    db: &TestDbPair,
    display_name: &str,
    plaintext_size: i64,
) -> (String, FileKey32) {
    db.insert_test_file(display_name, plaintext_size)
}
