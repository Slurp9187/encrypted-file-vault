// src/enums.rs
//! Public enum types used throughout the crate
//!
//! Central location for all #[derive(...)] enums that represent
//! user-visible choices: encryption algorithms, export formats, etc.

use serde::{Deserialize, Serialize};

/// Supported encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub enum EncryptionAlgorithm {
    #[default]
    AESCryptV3,
    // Future:
    // ChaCha20Poly1305,
    // XChaCha20Poly1305,
    // AES256GCM,
}

/// Future export formats (JSON, encrypted backup, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub enum ExportFormat {
    #[default]
    JsonV1,
    // EncryptedBackupV1,
    // PortableVaultV1,
}

/// Source of an import operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ImportSource {
    LegacyAescrypt,
    DirectoryScan,
    BackupFile,
}
