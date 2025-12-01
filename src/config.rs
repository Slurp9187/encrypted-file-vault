// src/config.rs
use serde::Deserialize;
use std::sync::OnceLock;

/// Global config — loaded once at startup
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

/// Load config at runtime — falls back to defaults if missing
pub fn load() -> &'static Config {
    CONFIG.get_or_init(|| {
        let config_path =
            std::env::var("EFV_CONFIG").unwrap_or_else(|_| "dev-config.toml".to_string());

        let mut conf: Config = if std::path::Path::new(&config_path).exists() {
            let content =
                std::fs::read_to_string(&config_path).expect("Failed to read dev-config.toml");
            toml::from_str(&content).expect("Invalid TOML in dev-config.toml")
        } else {
            eprintln!("Warning: dev-config.toml not found — using built-in defaults");
            Config {
                keys: Keys {
                    vault_key: "dev-vault-master-password-2025".into(),
                    index_key: "dev-index-password-2025".into(),
                },
                paths: Paths {
                    vault_db: "tests/data/vault.db".into(),
                    index_db: "tests/data/index.db".into(),
                },
                features: Features {
                    use_dev_keys: true,
                    skip_kdf_slowdown: true,
                    allow_insecure_export: true,
                },
            }
        };

        // Critical for tests: force real env-var keys instead of dev keys
        if std::env::var("EFV_TEST_MODE").is_ok() {
            conf.features.use_dev_keys = false;
        }

        conf
    })
}
