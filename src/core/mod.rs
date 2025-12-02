// src/core/mod.rs
pub mod crypto;
pub mod file;
pub mod index_db_ops;
pub mod key;
pub mod util;
pub mod vault_db_ops;

pub use crypto::*;
pub use file::*;
pub use index_db_ops::*;
pub use key::*;
pub use util::*;
pub use vault_db_ops::*;

// Keep only the absolute top-level public API here if needed
pub type Result<T> = std::result::Result<T, crate::error::CoreError>;
