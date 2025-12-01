// tests/common.rs
//! Central test utilities — the one place for all shared test code
//!
//! Import with: `use crate::common::*;` in every test file

#[cfg(feature = "logging")]
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub mod db {
    //! Database test fixtures — Fresh vs Persistent mode
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
        mode: DbMode,
        base_path: PathBuf,
    }

    impl TestDbPair {
        pub fn new(mode: DbMode) -> Self {
            let base = PathBuf::from("tests/data");
            fs::create_dir_all(&base).expect("create tests/data");

            let (subdir, index_name, vault_name) = match mode {
                DbMode::Fresh => ("db_fresh", "index.db", "vault.db"),
                DbMode::Persistent => ("db_persistent", "index.db", "vault.db"),
            };

            let subdir_path = base.join(subdir);
            fs::create_dir_all(&subdir_path).expect("create subdir");

            let index_path = subdir_path.join(index_name);
            let vault_path = subdir_path.join(vault_name);

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
                base_path: subdir_path,
            }
        }

        pub fn path(&self) -> &Path {
            &self.base_path
        }

        pub fn mode(&self) -> DbMode {
            self.mode
        }

        pub fn insert_test_file(
            &self,
            display_name: &str,
            plaintext_size: i64,
        ) -> (String, FileKey32) {
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
                        format!("/fake/{}.aes", display_name),
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

    // Legacy free function — kept for minimal friction
    pub fn insert_test_file(
        db: &TestDbPair,
        display_name: &str,
        plaintext_size: i64,
    ) -> (String, FileKey32) {
        db.insert_test_file(display_name, plaintext_size)
    }
}

/// Initialize test-friendly logging
pub fn setup_logging() {
    #[cfg(feature = "logging")]
    tracing_subscriber::registry()
        .with(fmt::layer().with_test_writer())
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

pub fn setup_logging_info() {
    #[cfg(feature = "logging")]
    tracing_subscriber::registry()
        .with(fmt::layer().with_test_writer())
        .with(EnvFilter::new("info"))
        .try_init()
        .ok();
}

// ——— TEST PRELUDE: The magic that eliminates 99% of secure-gate pain ———

pub use encrypted_file_vault::{
    aliases::FileKey32,
    consts::*,
    core::*,
    SecureConversionsExt, // .to_hex(), .to_base64(), etc.
    SecureRandomExt,      // .random() on fixed aliases
};

// Re-export our own helpers at the top level
pub use self::db::{insert_test_file, DbMode, TestDbPair};
