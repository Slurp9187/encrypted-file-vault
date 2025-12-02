// src/index.rs
use crate::consts::DB_KDF_ITERATIONS;
use rusqlite::{Connection, Result};
use std::{env, fs, path::Path};

pub fn open_index_db() -> Result<Connection> {
    let config = crate::config::load();

    let db_path = env::var("EFV_INDEX_DB").unwrap_or_else(|_| config.paths.index_db.clone());

    if let Some(parent) = Path::new(&db_path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    let conn = Connection::open(&db_path)?;

    let key: &str = if config.features.use_dev_keys {
        config.keys.index_key.as_str()
    } else {
        Box::leak(
            std::env::var("EFV_INDEX_KEY")
                .expect("EFV_INDEX_KEY required")
                .into_boxed_str(),
        )
    };

    conn.execute_batch(&format!(
        r#"
        PRAGMA key = '{key}';
        PRAGMA cipher_page_size = 4096;
        PRAGMA kdf_iter = {DB_KDF_ITERATIONS};
        PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
        PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;
        PRAGMA cipher_plaintext_header_size = 0;
        "#
    ))?;

    let _ = conn.execute(
        "ALTER TABLE files ADD COLUMN encryption_algo TEXT NOT NULL DEFAULT 'AESCryptV3'",
        [],
    );

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS files (
            file_id TEXT PRIMARY KEY,
            content_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            current_path TEXT NOT NULL,
            plaintext_size INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            rotated_at TEXT,
            encryption_algo TEXT NOT NULL DEFAULT 'AESCryptV3',
            filename_style TEXT NOT NULL DEFAULT 'human',
            id_length INTEGER NOT NULL DEFAULT 20,
            salted_with_path INTEGER NOT NULL DEFAULT 0,
            tags TEXT,
            note TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_content_hash ON files(content_hash);
        CREATE INDEX IF NOT EXISTS idx_display_name ON files(display_name);
        CREATE INDEX IF NOT EXISTS idx_current_path ON files(current_path);
        CREATE INDEX IF NOT EXISTS idx_encryption_algo ON files(encryption_algo);
        "#,
    )?;

    Ok(conn)
}
