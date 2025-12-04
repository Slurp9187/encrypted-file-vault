// src/aliases.rs
//! Re-exports secure-gate's ergonomic secret types
//!
//! These are the canonical types used throughout encrypted-file-vault.

pub use secure_gate::{
    dynamic_alias, fixed_alias, random_alias, SecureConversionsExt, SecureRandomExt,
};

// Fixed-size secrets
fixed_alias!(FileKey32, 32); // 256-bit AES-Crypt v3 file key
fixed_alias!(VaultKey32, 32); // Future: per-vault master key
fixed_alias!(IndexKey32, 32); // Future: separate index encryption key

// Dynamic secrets
dynamic_alias!(MasterPassword, String); // For legacy file upgrades
dynamic_alias!(UserPassphrase, String); // Future: vault unlock passphrase
dynamic_alias!(FilePassword, String); // Replacement for aescrypt-rs::Password (handles hex keys or legacy strings)
dynamic_alias!(CypherText, Vec<u8>);

// Random secrets
random_alias!(RandomPassword32, 32);
random_alias!(RandomFileKey32, 32);
