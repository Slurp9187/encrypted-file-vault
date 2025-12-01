// src/core.rs
//! Core cryptographic and vault operations — the beating heart of encrypted-file-vault

use std::io::{self, Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aescrypt_rs::{aliases::Password, convert::convert_to_v3, decrypt, encrypt};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use blake3::Hasher;
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

    // Fix #1: Extract the Vec while the MutexGuard is still alive
    let mut guard = buffer.lock().unwrap();
    let result = std::mem::take(&mut *guard);
    // guard is dropped here → lock released → buffer can be dropped safely
    Ok(result)
}

/// Fixed: decrypt_file — don't move plaintext after writing
pub fn decrypt_file<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    password: &Password,
) -> Result<u64> {
    let ciphertext = std::fs::read(input_path)?;
    let plaintext = decrypt_to_vec(&ciphertext, password)?;
    std::fs::write(&output_path, &plaintext)?; // borrow, don't move
    Ok(plaintext.len() as u64)
}

/// Rest of the file — unchanged and correct
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

pub fn store_key_blob(conn: &Connection, file_id: &str, key: &Key) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO keys (file_id, password_blob, created_at) VALUES (?1, ?2, datetime('now'))",
        params![file_id, key.expose_secret() as &[u8]],
    )?;
    Ok(())
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
    vault_conn: &Connection,
    index_conn: &Connection,
    filename_style: Option<&str>,
    id_length_hex: Option<u64>,
) -> Result<FileEntry> {
    let plaintext = std::fs::read(&plaintext_path)?;
    let key = generate_key();
    let password = Password::new(key.expose_secret().to_hex());

    encrypt_file(&plaintext_path, &encrypted_path, &password)?;

    let file_id = blake3_hex(&plaintext);

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
