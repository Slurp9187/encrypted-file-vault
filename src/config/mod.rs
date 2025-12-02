// src/config/mod.rs
//! Configuration system for encrypted-file-vault
//!
//! Central, lazy-loaded global config with TOML + env overrides.

pub use app::{load, Config};

mod app;
mod defaults;
// mod env;
