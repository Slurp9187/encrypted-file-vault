// tests/history_tests.rs
//! Tests for the new key-history feature

use std::fs;

use aescrypt_rs::aliases::Password;
use encrypted_file_vault::core::*;
use encrypted_file_vault::{index, vault};
use rusqlite::params;
use tempfile::tempdir;

/// Minimal tracing init – only active when the `logging` feature is enabled
#[cfg(feature = "logging")]
fn init_tracing() {
    use tracing_subscriber::prelude::*;
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_test_writer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}

#[cfg(not(feature = "logging"))]
fn init_tracing() {}

#[test]
fn test_store_key_blob_populates_history() {
    init_tracing();

    let _dir = tempdir().unwrap();
    std::env::set_var("EFV_VAULT_KEY", "test");

    let mut conn = vault::open_vault_db().unwrap();
    let key = generate_key();
    let file_id = "testfile1";

    store_key_blob(&mut conn, file_id, &key).unwrap();

    // Verify current key (via trigger)
    let current_blob: Vec<u8> = conn
        .query_row(
            "SELECT password_blob FROM keys WHERE file_id = ?1",
            [file_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(current_blob, key.expose_secret().as_slice());

    // Verify first history entry
    let (version, note, superseded_at): (i64, String, Option<String>) = conn
        .query_row(
            "SELECT version, note, superseded_at FROM key_history WHERE file_id = ?1",
            [file_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();

    assert_eq!(version, 1);
    assert_eq!(note, "initial");
    assert!(superseded_at.is_none());

    // Simulate an update
    let new_key = generate_key();
    store_key_blob(&mut conn, file_id, &new_key).unwrap();

    let (version, note, superseded_at): (i64, String, Option<String>) = conn
        .query_row(
            "SELECT version, note, superseded_at FROM key_history WHERE file_id = ?1 AND version = 2",
            [file_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();

    assert_eq!(version, 2);
    assert_eq!(note, "update");
    assert!(superseded_at.is_none());
}

#[test]
fn test_rotate_key_in_vault_updates_history() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    init_tracing();

    let dir = tempdir()?;
    let plain_path = dir.path().join("test.txt");
    let enc_path = dir.path().join("test.txt.aes");
    fs::write(&plain_path, b"test content")?;

    std::env::set_var("EFV_VAULT_KEY", "test-vault");
    std::env::set_var("EFV_INDEX_KEY", "test-index");

    let mut vault_conn = vault::open_vault_db()?;
    let index_conn = index::open_index_db()?;

    let entry = add_file(
        &plain_path,
        &enc_path,
        &mut vault_conn,
        &index_conn,
        None,
        None,
    )?;
    let file_id = entry.file_id.clone();
    let old_password = Password::new(entry.known_password_hex.unwrap());

    // Perform rotation
    let new_key = rotate_key_in_vault(
        &enc_path,
        &mut vault_conn,
        &index_conn,
        &file_id,
        &old_password,
        Some("test rotation"),
    )?;

    // Verify two history rows exist
    let mut stmt = vault_conn.prepare(
        "SELECT version, note, superseded_at FROM key_history WHERE file_id = ?1 ORDER BY version",
    )?;
    let mut rows = stmt.query(params![&file_id])?;

    // Version 1 (old)
    let row = rows.next()?.ok_or("missing history row 1")?;
    assert_eq!(row.get::<_, i64>(0)?, 1);
    assert_eq!(row.get::<_, String>(1)?, "initial");
    assert!(row.get::<_, Option<String>>(2)?.is_some());

    // Version 2 (new)
    let row = rows.next()?.ok_or("missing history row 2")?;
    assert_eq!(row.get::<_, i64>(0)?, 2);
    assert_eq!(row.get::<_, String>(1)?, "test rotation");
    assert!(row.get::<_, Option<String>>(2)?.is_none());

    // Current key in `keys` table
    let current_blob: Vec<u8> = vault_conn.query_row(
        "SELECT password_blob FROM keys WHERE file_id = ?1",
        [&file_id],
        |r| r.get(0),
    )?;
    assert_eq!(current_blob, new_key.expose_secret().as_slice());

    // Index rotated_at updated
    let rotated_at: Option<String> = index_conn.query_row(
        "SELECT rotated_at FROM files WHERE file_id = ?1",
        [&file_id],
        |r| r.get(0),
    )?;
    assert!(rotated_at.is_some());

    Ok(())
}

#[test]
fn test_history_backfill_on_existing_keys() -> std::result::Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let _dir = tempdir()?;
    std::env::set_var("EFV_VAULT_KEY", "test");

    // Insert directly into `keys` (simulate pre-history data)
    {
        let conn = vault::open_vault_db()?;
        let key = generate_key();
        let file_id = "backfill_test";

        conn.execute(
            "INSERT INTO keys (file_id, password_blob, created_at) VALUES (?1, ?2, datetime('now'))",
            params![file_id, key.expose_secret() as &[u8]],
        )?;

        // No history yet
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM key_history WHERE file_id = ?1",
            [file_id],
            |r| r.get(0),
        )?;
        assert_eq!(count, 0);
    }

    // Re-open → triggers backfill
    let conn = vault::open_vault_db()?;
    let file_id = "backfill_test";

    let (version, superseded_at): (i64, Option<String>) = conn.query_row(
        "SELECT version, superseded_at FROM key_history WHERE file_id = ?1",
        [file_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;

    assert_eq!(version, 1);
    assert!(superseded_at.is_none());

    Ok(())
}
