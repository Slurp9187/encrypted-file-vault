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
pub mod crypto;
pub mod db;
pub mod enums;
pub mod export;
pub mod key_ops;
pub mod legacy;
pub mod rotation;
pub mod util;

// Optional: flatter access (recommended)
pub use legacy::upgrade::upgrade_from_legacy;
pub use rotation::v3::rotate_key;

// Only ONE `mod error` — this is the correct one
pub mod error;

// Re-export everything users need at the crate root
pub use aliases::{FileKey32, SecureConversionsExt, SecureRandomExt};
pub use config::load as load_config;

pub use db::index_db_ops::FileEntry;
pub use db::vault_db_ops::add_file;

// pub use core::{PasswordRepr, Result as CoreResult};
pub use error::CoreError;
pub use export::export_to_json;
pub use key_ops::PasswordRepr;
// pub use key_ops::Result as CoreResult;

pub use db::{index_db_conn, index_db_ops, vault_db_conn, vault_db_ops};
