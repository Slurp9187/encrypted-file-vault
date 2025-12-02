// src/bin/decrypt_batch.rs
//! Genius Batch Decrypt — [Y/n/A] prompt + final cleanup sweep

use anyhow::{Context, Result};
use encrypted_file_vault::aliases::FilePassword;
use encrypted_file_vault::{core::decrypt_file, index_db_conn::open_index_db};
use rpassword::read_password;
use rusqlite::params;
use std::io::Write;
use tracing::{info, warn};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
struct PendingFile {
    path: std::path::PathBuf,
    path_str: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    info!("Encrypted File Vault — Genius Batch Decrypt v2");
    info!(
        "Y = decrypt now | n = skip | A = auto (try known passwords, ask only unknowns at end)\n"
    );

    let index_conn =
        open_index_db().context("Failed to open index database — is EFV_INDEX_KEY set?")?;

    index_conn
        .execute_batch("ALTER TABLE files ADD COLUMN known_password_hex TEXT;")
        .ok();

    // Load all known passwords once
    let mut known_passwords: Vec<FilePassword> = index_conn
        .prepare(
            "SELECT DISTINCT known_password_hex FROM files WHERE known_password_hex IS NOT NULL",
        )?
        .query_map([], |row| {
            let hex: String = row.get(0)?;
            Ok(FilePassword::new(hex))
        })?
        .filter_map(|r| r.ok())
        .collect();

    info!(
        "Loaded {} known password(s) from vault",
        known_passwords.len()
    );

    let mut decrypted_count = 0;
    let mut failed_count = 0;
    let mut pending_files = vec![];
    let mut last_password: Option<FilePassword> = None;

    // First pass: try known + last password, stash unknowns
    for entry in WalkDir::new(".")
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|s| s.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("aes"))
                .unwrap_or(false)
        })
    {
        let path = entry.path();
        if path.starts_with("./tests/data/output") {
            continue;
        }

        let path_str = path.to_str().context("non-UTF8 path")?.to_owned();
        let out_path = path.with_extension("decrypted");

        print!("Decrypt {} ? [Y/n/A] ", path.display());
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let choice = input.trim().to_ascii_lowercase();

        match choice.as_str() {
            "n" | "no" => {
                println!("  → skipped");
                continue;
            }
            "a" | "auto" | "all" => {
                // Try last password first
                if let Some(ref pwd) = last_password {
                    if decrypt_file(path, &out_path, pwd).is_ok() {
                        decrypted_count += 1;
                        info!("DECRYPTED (last pwd) → {}", out_path.display());
                        continue;
                    }
                }

                // Try all known passwords
                for pwd in &known_passwords {
                    if decrypt_file(path, &out_path, pwd).is_ok() {
                        decrypted_count += 1;
                        last_password = Some(pwd.clone());
                        info!("DECRYPTED (known pwd) → {}", out_path.display());
                        continue;
                    }
                }

                // Still unknown → stash for later
                pending_files.push(PendingFile {
                    path: path.to_owned(),
                    path_str,
                });
                println!("  → pending (unknown password)");
            }
            _ => {
                // Y or Enter → try last password, then ask
                if let Some(ref pwd) = last_password {
                    if decrypt_file(path, &out_path, pwd).is_ok() {
                        decrypted_count += 1;
                        info!("DECRYPTED (last pwd) → {}", out_path.display());
                        continue;
                    }
                }

                print!("Enter password for {}: ", path.display());
                std::io::stdout().flush()?;
                let pwd_input = read_password()?;
                let pwd = FilePassword::new(pwd_input.trim_end().to_owned());
                last_password = Some(pwd.clone());

                if decrypt_file(path, &out_path, &pwd).is_ok() {
                    decrypted_count += 1;
                    info!("DECRYPTED (new pwd) → {}", out_path.display());
                    known_passwords.push(pwd.clone());

                    // Save to DB
                    let pwd_hex = hex::encode(pwd.expose_secret().as_bytes());
                    save_password_to_db(&index_conn, &path_str, &pwd_hex)?;
                } else {
                    failed_count += 1;
                    warn!("FAILED {} — wrong password?", path.display());
                }
            }
        }
    }

    // FINAL CLEANUP SWEEP — only the true unknowns
    if !pending_files.is_empty() {
        println!(
            "\n=== FINAL CLEANUP: {} file(s) with unknown passwords ===",
            pending_files.len()
        );

        for pending in pending_files {
            let out_path = pending.path.with_extension("decrypted");

            print!("Enter password for {}: ", pending.path.display());
            std::io::stdout().flush()?;
            let input = read_password()?;
            let pwd = FilePassword::new(input.trim_end().to_owned());

            // last_password = Some(pwd.clone());

            if decrypt_file(&pending.path, &out_path, &pwd).is_ok() {
                decrypted_count += 1;
                info!("DECRYPTED → {}", out_path.display());
                known_passwords.push(pwd.clone());
                save_password_to_db(
                    &index_conn,
                    &pending.path_str,
                    &hex::encode(pwd.expose_secret().as_bytes()),
                )?;
            } else {
                failed_count += 1;
                warn!("FAILED {}", pending.path.display());
            }
        }
    }

    println!("\n=== BATCH COMPLETE ===");
    println!("Decrypted: {decrypted_count}");
    println!("Failed: {failed_count}");
    if failed_count == 0 {
        println!("Perfect! You're 100% clean!");
    }

    Ok(())
}

fn save_password_to_db(conn: &rusqlite::Connection, path_str: &str, pwd_hex: &str) -> Result<()> {
    let rows = conn.execute(
        "UPDATE files SET known_password_hex = ?1 WHERE current_path = ?2",
        params![pwd_hex, path_str],
    )?;
    if rows == 0 {
        let file_id = blake3::hash(path_str.as_bytes()).to_hex().to_string();
        conn.execute(
            "INSERT OR IGNORE INTO files (file_id, content_hash, display_name, current_path, plaintext_size, created_at, filename_style, id_length, known_password_hex)
             VALUES (?1, ?1, ?2, ?3, 0, datetime('now'), 'human', 64, ?4)",
            params![file_id, std::path::Path::new(path_str).file_name().unwrap().to_string_lossy(), path_str, pwd_hex],
        )?;
    }
    Ok(())
}
