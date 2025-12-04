// src/key_ops.rs
//! Key generation and representation utilities
//!
//! This module handles secure key generation and
//! multiple representations (hex, base64, etc.) for keys.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;

use crate::aliases::{FileKey32, RandomFileKey32, SecureConversionsExt, SecureRandomExt};

pub type Key = FileKey32;

/// Generate a new random 256-bit file key
#[inline]
pub fn generate_key() -> Key {
    Key::new(**RandomFileKey32::new())
}

/// Multiple string representations of a key for export/display
#[derive(Debug, Clone)]
pub struct PasswordRepr {
    pub hex: String,
    pub base64: String,
    pub base64url_no_pad: String,
}

pub fn password_representations(key: &Key) -> PasswordRepr {
    PasswordRepr {
        hex: key.expose_secret().to_hex(),
        base64: STANDARD.encode(key.expose_secret()),
        base64url_no_pad: URL_SAFE_NO_PAD.encode(key.expose_secret()),
    }
}
