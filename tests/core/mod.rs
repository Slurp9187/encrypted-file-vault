// tests/core/mod.rs

#[cfg(test)]
mod crypto;
#[cfg(test)]
mod file;
#[cfg(test)]
mod key;
#[cfg(test)]
mod util;
#[cfg(test)]
mod vault_workflow;

// Re-export for convenience if needed
pub use crypto::*;
pub use file::*;
pub use key::*;
pub use util::*;
pub use vault_workflow::*;
