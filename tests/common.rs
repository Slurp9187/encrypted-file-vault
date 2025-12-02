//! tests/common.rs
//! Central test utilities — shared across all test modules

#![allow(dead_code)]

use encrypted_file_vault::aliases::{FileKey32, SecureRandomExt};
use encrypted_file_vault::vault_db_ops::store_key_blob;
use encrypted_file_vault::{index_db_conn::open_index_db, vault_db_conn::open_vault_db};
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
    mode: DbMode,
    base_path: PathBuf,
}

impl TestDbPair {
    pub fn new(mode: DbMode) -> Self {
        let base = PathBuf::from("tests/data");

        if mode == DbMode::Fresh {
            let _ = fs::remove_dir_all(&base);
        }
        fs::create_dir_all(&base).expect("create tests/data");

        let (subdir, index_name, vault_name) = match mode {
            DbMode::Fresh => ("db_fresh", "index.db", "vault.db"),
            DbMode::Persistent => ("db_persistent", "index.db", "vault.db"),
        };

        let subdir_path = base.join(subdir);
        fs::create_dir_all(&subdir_path).expect("create subdir");

        let index_path = subdir_path.join(index_name);
        let vault_path = subdir_path.join(vault_name);

        // All tests run sequentially — safe to touch env vars
        unsafe {
            env::set_var("EFV_TEST_MODE", "1");
            env::set_var("EFV_VAULT_DB", &vault_path);
            env::set_var("EFV_INDEX_DB", &index_path);
            env::set_var("EFV_VAULT_KEY", "test-vault-secret-2025");
            env::set_var("EFV_INDEX_KEY", "test-index-secret-2025");
        }

        let vault = open_vault_db().expect("open vault db");
        let index = open_index_db().expect("open index db");

        Self {
            vault,
            index,
            mode,
            base_path: subdir_path,
        }
    }

    #[inline]
    pub fn path(&self) -> &Path {
        &self.base_path
    }

    #[inline]
    pub fn mode(&self) -> DbMode {
        self.mode
    }

    /// Insert a fake file using the SAME connection → trigger fires → keys table populated
    pub fn insert_test_file(
        &mut self,
        display_name: &str,
        plaintext_size: i64,
    ) -> (String, FileKey32) {
        let key = FileKey32::random();
        let file_id = blake3::hash(key.expose_secret()).to_hex().to_string();

        store_key_blob(&mut self.vault, &file_id, &key).expect("store key blob");

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
                    format!("/fake/{}.aes", display_name),
                    plaintext_size,
                    "human",
                    64i64,
                ],
            )
            .expect("insert into index");

        (file_id, key)
    }
}

impl Default for TestDbPair {
    fn default() -> Self {
        Self::new(DbMode::Fresh)
    }
}
