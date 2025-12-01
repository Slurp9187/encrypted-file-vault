// src/error.rs
//! Public error type for the entire crate

use aescrypt_rs::AescryptError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Crypto operation failed: {0}")]
    Crypto(AescryptError),

    #[error("Database error: {0}")]
    Sql(#[from] rusqlite::Error),
}

impl From<AescryptError> for CoreError {
    fn from(err: AescryptError) -> Self {
        CoreError::Crypto(err)
    }
}
