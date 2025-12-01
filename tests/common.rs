// tests/common.rs
//! Shared test utilities — professional logging setup

#[cfg(feature = "logging")]
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialize beautiful, test-friendly logging
/// Call once at the start of any test that needs logs
pub fn setup() {
    #[cfg(feature = "logging")]
    tracing_subscriber::registry()
        .with(fmt::layer().with_test_writer()) // pretty + works in `cargo test`
        .with(EnvFilter::from_default_env()) // respects RUST_LOG=
        .try_init()
        .ok(); // idempotent — safe to call multiple times

    #[cfg(not(feature = "logging"))]
    { /* no-op */ }
}

/// Force info-level logging even if RUST_LOG is not set
pub fn setup_info() {
    #[cfg(feature = "logging")]
    tracing_subscriber::registry()
        .with(fmt::layer().with_test_writer())
        .with(EnvFilter::new("info"))
        .try_init()
        .ok();

    #[cfg(not(feature = "logging"))]
    { /* no-op */ }
}
