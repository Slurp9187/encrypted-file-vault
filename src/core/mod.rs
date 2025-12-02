// src/core/mod.rs
pub mod file;

pub use file::*;

// Keep only the absolute top-level public API here if needed
pub type Result<T> = std::result::Result<T, crate::error::CoreError>;
