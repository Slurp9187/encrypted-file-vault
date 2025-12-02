//! Vault database operations and high-level workflows
//!
//! This module handles key storage in the vault DB,
//! including history tracking and atomic rotations.
//! It also includes top-level workflows like add_file
//! that coordinate crypto, file I/O, and both DBs.

use std::path::Path;

use crate::aliases::FilePassword;
use rusqlite::{params, Connection};

use crate::aliases::SecureConversionsExt;
use crate::consts::{DEFAULT_FILENAME_STYLE, DEFAULT_ID_LENGTH_HEX};
use crate::core::file::encrypt_file;
use crate::core::key::{generate_key, Key};
use crate::crypto::rotate_key;
use crate::db::index_db_ops::{store_file_entry, FileEntry};
use crate::error::CoreError;
use crate::util::blake3_hex;
use crate::CoreResult as Result;

/// Store a new key blob into key_history (triggers keep keys table in sync)
pub fn store_key_blob(conn: &mut Connection, file_id: &str, key: &Key) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    // Get next version number
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
    // 1. Crypto rotation
    let ciphertext = std::fs::read(encrypted_path.as_ref())?;
    let (new_ciphertext, new_key) = rotate_key(&ciphertext, old_password)?;
    std::fs::write(encrypted_path.as_ref(), new_ciphertext)?;
    // 2. DB transaction
    let tx = vault_conn.transaction().map_err(CoreError::Sql)?;
    // Get current version
    let current_version: i64 = tx.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM key_history WHERE file_id = ?1",
        [file_id],
        |row| row.get(0),
    )?;
    if current_version == 0 {
        return Err(CoreError::Sql(rusqlite::Error::QueryReturnedNoRows));
    }
    let new_version = current_version + 1;
    // Mark previous version as superseded
    tx.execute(
        "UPDATE key_history SET superseded_at = datetime('now')
         WHERE file_id = ?1 AND version = ?2",
        params![file_id, current_version],
    )
    .map_err(CoreError::Sql)?;
    // Insert new version
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
    // Commit before index update (still atomic enough for our threat model)
    tx.commit().map_err(CoreError::Sql)?;
    // Update index DB
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
    let plaintext = std::fs::read(plaintext_path.as_ref())?;
    let key = generate_key();
    let password = FilePassword::new(key.expose_secret().to_hex());
    encrypt_file(plaintext_path.as_ref(), encrypted_path.as_ref(), &password)?;
    let file_id = blake3_hex(&plaintext);
    // This now correctly inserts into key_history (version 1, note="initial")
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
        plaintext_size: plaintext.len() as u64,
        filename_style: filename_style.unwrap_or(DEFAULT_FILENAME_STYLE).to_string(),
        id_length_hex: id_length_hex.unwrap_or(DEFAULT_ID_LENGTH_HEX as u64),
        known_password_hex: Some(key.expose_secret().to_hex()),
    };
    store_file_entry(index_conn, &entry)?;
    Ok(entry)
}
