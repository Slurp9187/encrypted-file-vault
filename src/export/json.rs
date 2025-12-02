// src/export/json.rs
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use secure_gate::dynamic_alias;
use serde_json::json;
use std::error::Error;

use crate::db::{index_db_conn::open_index_db, vault_db_conn::open_vault_db};

// Your alias — perfect
dynamic_alias!(PasswordBlob, Vec<u8>);

/// Export all file metadata + passwords to a portable JSON file using Base64URL encoding.
///
/// SECURITY WARNING: This file contains every password in cleartext.
/// Protect it like nuclear launch codes.
pub fn export_to_json(path: &str) -> Result<(), Box<dyn Error>> {
    let index_conn = open_index_db()?;
    let vault_conn = open_vault_db()?;

    let mut stmt = index_conn.prepare(
        r#"
        SELECT 
            f.file_id,
            f.display_name,
            f.current_path,
            f.plaintext_size,
            f.created_at,
            f.rotated_at,
            f.tags,
            f.note,
            f.content_hash,
            f.filename_style,
            f.id_length
        FROM files f
        ORDER BY f.display_name
        "#,
    )?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,         // file_id
            row.get::<_, String>(1)?,         // display_name
            row.get::<_, String>(2)?,         // current_path
            row.get::<_, i64>(3)?,            // plaintext_size
            row.get::<_, String>(4)?,         // created_at
            row.get::<_, Option<String>>(5)?, // rotated_at
            row.get::<_, Option<String>>(6)?, // tags
            row.get::<_, Option<String>>(7)?, // note
            row.get::<_, String>(8)?,         // content_hash
            row.get::<_, String>(9)?,         // filename_style
            row.get::<_, i64>(10)?,           // id_length
        ))
    })?;

    let mut files = Vec::new();

    for row in rows {
        let (
            file_id,
            display_name,
            current_path,
            plaintext_size,
            created_at,
            rotated_at,
            tags,
            note,
            content_hash,
            filename_style,
            id_length,
        ) = row?;

        // Fetch raw BLOB → convert directly into your secure-gate alias
        let password_blob: PasswordBlob = vault_conn.query_row(
            "SELECT password_blob FROM keys WHERE file_id = ?1",
            [&file_id],
            |r| {
                let raw: Vec<u8> = r.get(0)?;
                Ok(PasswordBlob::new(raw)) // ← wraps and zeroizes on drop
            },
        )?;

        // expose_secret() works because ExposeSecret is in scope
        let password_b64 = URL_SAFE_NO_PAD.encode(password_blob.expose_secret());

        files.push(json!({
            "file_id": file_id,
            "content_hash": content_hash,
            "display_name": display_name,
            "current_path": current_path,
            "plaintext_size_bytes": plaintext_size,
            "password_base64url": password_b64,
            "created_at": created_at,
            "rotated_at": rotated_at,
            "tags": tags,
            "note": note,
            "filename_style": filename_style,
            "id_length_hex_chars": id_length,
        }));
    }

    let export = json!({
        "export_format": "encrypted-file-vault-v1",
        "exported_at": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "exporter_version": env!("CARGO_PKG_VERSION"),
        "total_files": files.len(),
        "warning": "THIS FILE CONTAINS ALL PASSWORDS IN PLAINTEXT. ENCRYPT OR DELETE IMMEDIATELY AFTER USE.",
        "files": files
    });

    std::fs::write(path, serde_json::to_string_pretty(&export)?)?;
    println!("Exported {} file(s) → {}", files.len(), path);
    println!("SECURITY: This file is extremely sensitive — encrypt it now!");

    Ok(())
}
