// src/config/app.rs
use super::defaults::*;
use serde::Deserialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub keys: Keys,
    pub paths: Paths,
    pub features: Features,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Keys {
    pub vault_key: String,
    pub index_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Paths {
    pub vault_db: String,
    pub index_db: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Features {
    pub use_dev_keys: bool,
    pub skip_kdf_slowdown: bool,
    pub allow_insecure_export: bool,
}

static CONFIG: OnceLock<Config> = OnceLock::new();

pub fn load() -> &'static Config {
    CONFIG.get_or_init(|| {
        let config_path =
            std::env::var("EFV_CONFIG").unwrap_or_else(|_| "dev-config.toml".to_string());

        let mut conf = if std::path::Path::new(&config_path).exists() {
            let content =
                std::fs::read_to_string(&config_path).expect("Failed to read dev-config.toml");
            toml::from_str(&content).expect("Invalid TOML in dev-config.toml")
        } else {
            eprintln!("Warning: dev-config.toml not found — using built-in defaults");
            Config {
                keys: default_keys(),
                paths: default_paths(),
                features: default_features(),
            }
        };

        // Test mode override
        if std::env::var("EFV_TEST_MODE").is_ok() {
            conf.features.use_dev_keys = false;
        }

        conf
    })
}
