// src/core/mod.rs
pub mod file;
pub mod key;

pub use file::*;
pub use key::*;

// Keep only the absolute top-level public API here if needed
pub type Result<T> = std::result::Result<T, crate::error::CoreError>;
