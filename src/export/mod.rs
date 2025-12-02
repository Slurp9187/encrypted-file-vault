// src/export/mod.rs
//! Export utilities for encrypted-file-vault
//!
//! Supports multiple formats: JSON, CSV, Bitwarden, etc.
//! All exports are insecure by design (plaintext passwords) — warn users heavily.

pub use json::export_to_json;
// pub use csv::export_to_csv;         // Future
// pub use bitwarden::export_bitwarden; // Future

pub mod json;
// mod csv;          // Future
// mod bitwarden;    // Future
