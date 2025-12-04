//! Vault database operations and high-level workflows

use std::path::Path;

use crate::aliases::{FilePassword, PlainText};
use crate::consts::{DEFAULT_FILENAME_STYLE, DEFAULT_ID_LENGTH_HEX};
use crate::crypto::rotate_key_streaming;
use crate::db::index_db_ops::{store_file_entry, FileEntry};
use crate::error::CoreError;
use crate::file_ops::encrypt_file;
use crate::key_ops::{generate_key, Key};
use crate::util::blake3_hex;
use rusqlite::{params, Connection};
use secure_gate::SecureConversionsExt; // ← FIXED: needed for .to_hex()

use crate::Result;

/// Store a new key blob into key_history (triggers keep keys table in sync)
pub fn store_key_blob(conn: &mut Connection, file_id: &str, key: &Key) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    let version: i64 = tx.query_row(
        "SELECT COALESCE(MAX(version), 0) + 1 FROM key_history WHERE file_id = ?1",
        [file_id],
        |row| row.get(0),
    )?;
    let note = if version == 1 { "initial" } else { "update" };
    tx.execute(
        "INSERT INTO key_history (file_id, version, password_blob, note)
         VALUES (?1, ?2, ?3, ?4)",
        params![file_id, version, key.expose_secret() as &[u8], note],
    )?;
    tx.commit()?;
    Ok(())
}

/// Full vault-aware key rotation: re-encrypts file + updates key_history atomically
pub fn rotate_key_in_vault<P: AsRef<Path>>(
    encrypted_path: P,
    vault_conn: &mut Connection,
    index_conn: &Connection,
    file_id: &str,
    old_password: &FilePassword,
    note: Option<&str>,
) -> Result<Key> {
    let path = encrypted_path.as_ref();
    let temp_path = path.with_extension("tmp-rotate");

    let new_key = {
        let input = std::fs::File::open(path)?;
        let output = std::fs::File::create(&temp_path)?;
        rotate_key_streaming(input, output, old_password)?
    };

    std::fs::rename(&temp_path, path)?;

    let tx = vault_conn.transaction().map_err(CoreError::Sql)?;
    let current_version: i64 = tx.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM key_history WHERE file_id = ?1",
        [file_id],
        |row| row.get(0),
    )?;
    if current_version == 0 {
        return Err(CoreError::Sql(rusqlite::Error::QueryReturnedNoRows));
    }
    let new_version = current_version + 1;

    tx.execute(
        "UPDATE key_history SET superseded_at = datetime('now')
         WHERE file_id = ?1 AND version = ?2",
        params![file_id, current_version],
    )
    .map_err(CoreError::Sql)?;

    tx.execute(
        "INSERT INTO key_history (file_id, version, password_blob, note)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            file_id,
            new_version,
            new_key.expose_secret() as &[u8],
            note.unwrap_or("rotation")
        ],
    )
    .map_err(CoreError::Sql)?;

    tx.commit().map_err(CoreError::Sql)?;

    index_conn
        .execute(
            "UPDATE files SET rotated_at = datetime('now') WHERE file_id = ?1",
            [file_id],
        )
        .map_err(CoreError::Sql)?;

    Ok(new_key)
}

/// Add a new file to the vault: encrypt, store key, index metadata
pub fn add_file<P: AsRef<Path>>(
    plaintext_path: P,
    encrypted_path: P,
    vault_conn: &mut Connection,
    index_conn: &Connection,
    filename_style: Option<&str>,
    id_length_hex: Option<u64>,
) -> Result<FileEntry> {
    let plaintext = PlainText::new(std::fs::read(plaintext_path.as_ref())?);
    let key = generate_key();
    let password = FilePassword::new(key.expose_secret().to_hex());

    encrypt_file(plaintext_path.as_ref(), encrypted_path.as_ref(), &password)?;

    let file_id = blake3_hex(plaintext.expose_secret());

    store_key_blob(vault_conn, &file_id, &key)?;

    let entry = FileEntry {
        file_id: file_id.clone(),
        content_hash: file_id,
        display_name: plaintext_path
            .as_ref()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string(),
        current_path: encrypted_path.as_ref().to_path_buf(),
        plaintext_size: plaintext.expose_secret().len() as u64,
        filename_style: filename_style.unwrap_or(DEFAULT_FILENAME_STYLE).to_string(),
        id_length_hex: id_length_hex.unwrap_or(DEFAULT_ID_LENGTH_HEX as u64),
        known_password_hex: Some(key.expose_secret().to_hex()),
    };

    store_file_entry(index_conn, &entry)?;
    Ok(entry)
}
