// src/vault.rs
use crate::consts::DB_KDF_ITERATIONS;
use rusqlite::{Connection, Result};
use std::{env, fs, path::Path};

pub fn open_vault_db() -> Result<Connection> {
    let config = crate::config::load();

    // Allow full test isolation via env vars
    let db_path = env::var("EFV_VAULT_DB").unwrap_or_else(|_| config.paths.vault_db.clone());

    if let Some(parent) = Path::new(&db_path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    let conn = Connection::open(&db_path)?;

    let key: &str = if config.features.use_dev_keys {
        config.keys.vault_key.as_str()
    } else {
        Box::leak(
            std::env::var("EFV_VAULT_KEY")
                .expect("EFV_VAULT_KEY required")
                .into_boxed_str(),
        )
    };

    conn.execute_batch(&format!("PRAGMA key = '{key}';"))?;
    conn.execute_batch(&format!(
        r#"
        PRAGMA cipher_page_size = 4096;
        PRAGMA kdf_iter = {DB_KDF_ITERATIONS};
        PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
        PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;
        PRAGMA cipher_plaintext_header_size = 0;

        CREATE TABLE IF NOT EXISTS keys (
            file_id TEXT PRIMARY KEY,
            password_blob BLOB NOT NULL,
            created_at TEXT NOT NULL,
            rotated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS key_history (
            file_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            password_blob BLOB NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            superseded_at TEXT,
            note TEXT,
            PRIMARY KEY (file_id, version)
        );

        CREATE INDEX IF NOT EXISTS idx_key_history_file_id ON key_history(file_id);

        -- Back-fill history for legacy rows
        INSERT OR IGNORE INTO key_history (file_id, version, password_blob, created_at)
        SELECT file_id, 1, password_blob, created_at FROM keys;

        -- Keep `keys` table always in sync with latest version
        CREATE TRIGGER IF NOT EXISTS sync_current_key_after_insert
        AFTER INSERT ON key_history
        WHEN NEW.superseded_at IS NULL
        BEGIN
            INSERT OR REPLACE INTO keys (file_id, password_blob, created_at, rotated_at)
            VALUES (NEW.file_id, NEW.password_blob, NEW.created_at, NULL);
        END;
        "#
    ))?;

    Ok(conn)
}
