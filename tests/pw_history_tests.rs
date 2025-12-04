// tests/history_tests.rs
//! Tests for the new key-history feature

use encrypted_file_vault::add_file;
use encrypted_file_vault::aliases::FilePassword;
use encrypted_file_vault::key_ops::generate_key;
use encrypted_file_vault::vault_db_conn;
use encrypted_file_vault::vault_db_ops::rotate_key_in_vault;
use encrypted_file_vault::vault_db_ops::store_key_blob;
use rusqlite::params;
use std::fs;
use tempfile::tempdir;

// Shared test helper — fresh DBs every test
mod common;
use common::{DbMode, TestDbPair};

// Use the REAL std::result::Result (two generics) for test functions
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn test_store_key_blob_populates_history() {
    // Explicitly use Fresh mode — these are unit-style tests
    let mut db = TestDbPair::new(DbMode::Fresh);

    let key = generate_key();
    let file_id = "testfile1";

    store_key_blob(&mut db.vault, file_id, &key).unwrap();

    // Current key (via trigger)
    let current_blob: Vec<u8> = db
        .vault
        .query_row(
            "SELECT password_blob FROM keys WHERE file_id = ?1",
            [file_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(current_blob, key.expose_secret().as_slice());

    // First history entry
    let (version, note, superseded_at): (i64, String, Option<String>) = db
        .vault
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
    store_key_blob(&mut db.vault, file_id, &new_key).unwrap();

    let (version, note, superseded_at): (i64, String, Option<String>) = db
        .vault
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
fn test_rotate_key_in_vault_updates_history() -> TestResult {
    let mut db = TestDbPair::new(DbMode::Fresh);

    let dir = tempdir()?;
    let plain_path = dir.path().join("test.txt");
    let enc_path = dir.path().join("test.txt.aes");
    fs::write(&plain_path, b"test content")?;

    let entry = add_file(&plain_path, &enc_path, &mut db.vault, &db.index, None, None)?;

    let file_id = entry.file_id.clone();
    let old_password = FilePassword::new(entry.known_password_hex.unwrap());

    let new_key = rotate_key_in_vault(
        &enc_path,
        &mut db.vault,
        &db.index,
        &file_id,
        &old_password,
        Some("test rotation"),
    )?;

    // Verify history rows
    let mut stmt = db.vault.prepare(
        "SELECT version, note, superseded_at FROM key_history WHERE file_id = ?1 ORDER BY version",
    )?;
    let mut rows = stmt.query(params![&file_id])?;

    // Version 1 – old key
    let row = rows.next()?.ok_or("missing history row 1")?;
    assert_eq!(row.get::<_, i64>(0)?, 1);
    assert_eq!(row.get::<_, String>(1)?, "initial");
    assert!(row.get::<_, Option<String>>(2)?.is_some());

    // Version 2 – new key
    let row = rows.next()?.ok_or("missing history row 2")?;
    assert_eq!(row.get::<_, i64>(0)?, 2);
    assert_eq!(row.get::<_, String>(1)?, "test rotation");
    assert!(row.get::<_, Option<String>>(2)?.is_none());

    // Current key in `keys` table
    let current_blob: Vec<u8> = db.vault.query_row(
        "SELECT password_blob FROM keys WHERE file_id = ?1",
        [&file_id],
        |r| r.get(0),
    )?;
    assert_eq!(current_blob, new_key.expose_secret().as_slice());

    // Index rotated_at updated
    let rotated_at: Option<String> = db.index.query_row(
        "SELECT rotated_at FROM files WHERE file_id = ?1",
        [&file_id],
        |r| r.get(0),
    )?;
    assert!(rotated_at.is_some());

    Ok(())
}

#[test]
fn test_history_backfill_on_existing_keys() -> TestResult {
    let db = TestDbPair::new(DbMode::Fresh);

    // Insert directly into `keys` (simulate legacy data)
    {
        let key = generate_key();
        let file_id = "backfill_test";
        db.vault.execute(
            "INSERT INTO keys (file_id, password_blob, created_at) VALUES (?1, ?2, datetime('now'))",
            params![file_id, key.expose_secret() as &[u8]],
        )?;

        let count: i64 = db.vault.query_row(
            "SELECT COUNT(*) FROM key_history WHERE file_id = ?1",
            [file_id],
            |r| r.get(0),
        )?;
        assert_eq!(count, 0);
    }

    // Re-open → backfill runs
    drop(db.vault);
    let vault_conn = vault_db_conn::open_vault_db()?;
    let file_id = "backfill_test";

    let (version, superseded_at): (i64, Option<String>) = vault_conn.query_row(
        "SELECT version, superseded_at FROM key_history WHERE file_id = ?1",
        [file_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;

    assert_eq!(version, 1);
    assert!(superseded_at.is_none());

    Ok(())
}
