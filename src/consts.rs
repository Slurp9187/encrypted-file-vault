// src/consts.rs
//! Shared constants — security parameters and defaults

/// Recommended KDF iterations for SQLCipher databases (2025+)
// ~0.1–0.2s on modern hardware — good default
pub const DB_KDF_ITERATIONS: u32 = 256_000;

/// High-security KDF iterations for per-file keys (AES-Crypt v3)
// 600_000 ≈ 0.5–1 second on typical CPU — defense against GPU cracking
pub const FILE_KDF_ITERATIONS: u32 = 600_000;

/// Default number of hex characters shown in human-readable filenames
pub const DEFAULT_ID_LENGTH_HEX: i64 = 20;

/// Default filename style
pub const DEFAULT_FILENAME_STYLE: &str = "human";

/// Current supported encryption algorithm
pub const DEFAULT_ENCRYPTION_ALGO: &str = "AESCryptV3";

/// Header magic for AES-Crypt v3 files
pub const AESCRYPT_V3_HEADER: &[u8; 5] = b"AES\x03\x00";
