// src/algo.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive] // so we can add more later
#[derive(Default)]
pub enum EncryptionAlgorithm {
    #[default]
    AESCryptV3,
    // Future:
    // ChaCha20Poly1305,
    // XChaCha20Poly1305,
    // AES256GCM,
}
