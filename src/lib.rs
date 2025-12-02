// src/lib.rs
//! encrypted-file-vault — A secure, content-addressed file vault
//!
//! Features:
//! - AES Crypt v3 encryption
//! - BLAKE3 file IDs
//! - Split vault + index databases
//! - Full secure-gate v0.5.8 integration

pub mod aliases;
pub mod config;
pub mod consts;
pub mod core;
pub mod export;
pub mod index_db_conn;
pub mod legacy;
pub mod rotation;
pub mod vault_db_conn;

// Optional: flatter access (recommended)
pub use legacy::upgrade::upgrade_from_legacy;
pub use rotation::v3::rotate_key;

// Only ONE `mod error` — this is the correct one
pub mod error;

// Re-export everything users need at the crate root
pub use aliases::{FileKey32, SecureConversionsExt, SecureRandomExt};
pub use config::load as load_config;
// pub use core::decrypt_file;
// pub use core::encrypt_file;
pub use core::{add_file, FileEntry, PasswordRepr, Result as CoreResult};
pub use error::CoreError;
pub use export::export_to_json;
