//! Index database operations for file metadata
//!
//! This module handles storing and structuring file entries
//! in the index database. It does not include DB connection logic
//! (see crate::index for open_index_db).

use std::path::PathBuf;

use rusqlite::{params, Connection};

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

/// Store or update a file entry in the index database
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
