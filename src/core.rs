// src/core.rs
//! Core cryptographic and vault operations — the beating heart of encrypted-file-vault

use std::io::{self, Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aescrypt_rs::{aliases::Password, convert::convert_to_v3, decrypt, encrypt};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use blake3::Hasher;
// use rusqlite::Transaction;
use rusqlite::{params, Connection};
use secure_gate::SecureConversionsExt;

use crate::aliases::{FileKey32, SecureRandomExt};
use crate::consts::{
    AESCRYPT_V3_HEADER, DEFAULT_FILENAME_STYLE, DEFAULT_ID_LENGTH_HEX, FILE_KDF_ITERATIONS,
};
use crate::error::CoreError;

pub type Result<T> = std::result::Result<T, CoreError>;

/// 256-bit file encryption key — automatically zeroizes on drop
pub type Key = FileKey32;

#[inline]
pub fn generate_key() -> Key {
    Key::random()
}

pub fn blake3_hex(data: &[u8]) -> String {
    Hasher::new().update(data).finalize().to_hex().to_string()
}

pub fn encrypt_to_vec(plaintext: &[u8], password: &Password) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encrypt(
        Cursor::new(plaintext),
        &mut out,
        password,
        FILE_KDF_ITERATIONS,
    )
    .map_err(CoreError::Crypto)?;
    Ok(out)
}

pub fn decrypt_to_vec(ciphertext: &[u8], password: &Password) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    decrypt(Cursor::new(ciphertext), &mut out, password).map_err(CoreError::Crypto)?;
    Ok(out)
}

/// Thread-safe writer used when aescrypt_rs takes the writer by value
#[derive(Clone)]
pub(crate) struct ThreadSafeVec(Arc<Mutex<Vec<u8>>>);

impl Write for ThreadSafeVec {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Fixed: ensure_v3 — extract data BEFORE buffer is dropped
pub fn ensure_v3(ciphertext: Vec<u8>, password: &Password) -> Result<Vec<u8>> {
    if ciphertext.get(..5) == Some(AESCRYPT_V3_HEADER) {
        return Ok(ciphertext);
    }

    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = ThreadSafeVec(buffer.clone());

    convert_to_v3(
        Cursor::new(ciphertext),
        writer,
        password,
        FILE_KDF_ITERATIONS,
    )
    .map_err(CoreError::Crypto)?;

    let mut guard = buffer.lock().unwrap();
    let result = std::mem::take(&mut *guard);
    Ok(result)
}

pub fn decrypt_file<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    password: &Password,
) -> Result<u64> {
    let ciphertext = std::fs::read(input_path)?;
    let plaintext = decrypt_to_vec(&ciphertext, password)?;
    std::fs::write(&output_path, &plaintext)?;
    Ok(plaintext.len() as u64)
}

/// Pure crypto rotation — no DB involvement
pub fn rotate_key(ciphertext: &[u8], old_password: &Password) -> Result<(Vec<u8>, Key)> {
    let v3 = ensure_v3(ciphertext.to_vec(), old_password)?;
    let plaintext = decrypt_to_vec(&v3, old_password)?;
    let new_key = generate_key();
    let new_password = Password::new(new_key.expose_secret().to_hex());
    let new_ciphertext = encrypt_to_vec(&plaintext, &new_password)?;
    Ok((new_ciphertext, new_key))
}

pub fn encrypt_file<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    password: &Password,
) -> Result<u64> {
    let plaintext = std::fs::read(input_path)?;
    let ciphertext = encrypt_to_vec(&plaintext, password)?;
    std::fs::write(output_path, ciphertext)?;
    Ok(plaintext.len() as u64)
}

/// Store a key blob + insert into key_history (trigger keeps `keys` table in sync)
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

/// Full vault-aware rotation: re-encrypts file + atomically updates key_history
pub fn rotate_key_in_vault<P: AsRef<Path>>(
    encrypted_path: P,
    vault_conn: &mut Connection,
    index_conn: &Connection,
    file_id: &str,
    old_password: &Password,
    note: Option<&str>,
) -> Result<Key> {
    // 1. Crypto rotation
    let ciphertext = std::fs::read(&encrypted_path)?;
    let (new_ciphertext, new_key) = rotate_key(&ciphertext, old_password)?;
    std::fs::write(&encrypted_path, new_ciphertext)?;
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

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub file_id: String,
    pub content_hash: String,
    pub display_name: String,
    pub current_path: PathBuf,
    pub plaintext_size: u64,
    pub filename_style: String,
    pub id_length_hex: u64,
    pub known_password_hex: Option<String>,
}

pub fn store_file_entry(conn: &Connection, entry: &FileEntry) -> rusqlite::Result<()> {
    conn.execute(
        r#"
        INSERT OR REPLACE INTO files (
            file_id, content_hash, display_name, current_path,
            plaintext_size, created_at, filename_style, id_length
        ) VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'), ?6, ?7)
        "#,
        params![
            &entry.file_id,
            &entry.content_hash,
            &entry.display_name,
            entry.current_path.to_str().unwrap(),
            entry.plaintext_size as i64,
            &entry.filename_style,
            entry.id_length_hex as i64,
        ],
    )?;
    Ok(())
}

pub fn add_file<P: AsRef<Path>>(
    plaintext_path: P,
    encrypted_path: P,
    vault_conn: &mut Connection,
    index_conn: &Connection,
    filename_style: Option<&str>,
    id_length_hex: Option<u64>,
) -> Result<FileEntry> {
    let plaintext = std::fs::read(&plaintext_path)?;
    let key = generate_key();
    let password = Password::new(key.expose_secret().to_hex());
    encrypt_file(&plaintext_path, &encrypted_path, &password)?;
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

#[derive(Debug, Clone)]
pub struct PasswordRepr {
    pub hex: String,
    pub base64: String,
    pub base64url_no_pad: String,
}

pub fn password_representations(key: &Key) -> PasswordRepr {
    PasswordRepr {
        hex: key.expose_secret().to_hex(),
        base64: STANDARD.encode(key.expose_secret()),
        base64url_no_pad: URL_SAFE_NO_PAD.encode(key.expose_secret()),
    }
}

pub fn is_aescrypt_file(data: &[u8]) -> bool {
    data.get(..3) == Some(b"AES")
}

pub fn aescrypt_version(data: &[u8]) -> Option<u8> {
    data.get(3).copied()
}
