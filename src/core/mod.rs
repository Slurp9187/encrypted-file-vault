// src/core/mod.rs
pub mod file;
pub mod key;
pub mod util;

pub use file::*;
pub use key::*;
pub use util::*;

// Keep only the absolute top-level public API here if needed
pub type Result<T> = std::result::Result<T, crate::error::CoreError>;
