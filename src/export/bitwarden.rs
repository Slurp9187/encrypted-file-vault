// src/export/bitwarden.rs
// Future: export to Bitwarden format (e.g., JSON/CSV for import)
use std::error::Error;

// Stub — implement when ready (e.g., custom mapping to Bitwarden fields)
pub fn export_bitwarden(path: &str) -> Result<(), Box<dyn Error>> {
    // TODO: Map vault data to Bitwarden login items (name, username=display_name, password=password_b64, notes=content_hash + tags)
    unimplemented!("Bitwarden export coming soon");
}
