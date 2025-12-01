// src/core/mod.rs
pub mod crypto;
pub mod file;
pub mod index;
pub mod key;
pub mod util;
pub mod vault;

pub use crypto::*;
pub use file::*;
pub use index::*;
pub use key::*;
pub use util::*;
pub use vault::*;

// Keep only the absolute top-level public API here if needed
pub type Result<T> = std::result::Result<T, crate::error::CoreError>;
