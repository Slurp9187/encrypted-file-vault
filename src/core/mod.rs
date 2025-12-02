// src/core/mod.rs
pub mod file_ops;

pub use file_ops::*;

// Keep only the absolute top-level public API here if needed
pub type Result<T> = std::result::Result<T, crate::error::CoreError>;
