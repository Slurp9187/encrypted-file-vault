use std::{fs, path::Path};

use rusqlite::{Connection, Result};

use crate::consts::DB_KDF_ITERATIONS;

// src/vault.rs
pub fn open_vault_db() -> Result<Connection> {
    let config = crate::config::load();
    let db_path = &config.paths.vault_db;

    if let Some(parent) = Path::new(db_path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    let conn = Connection::open(db_path)?;

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
            file_id       TEXT PRIMARY KEY,
            password_blob BLOB NOT NULL,
            created_at    TEXT NOT NULL,
            rotated_at    TEXT
        );
        "#
    ))?;

    Ok(conn)
}
