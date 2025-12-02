// src/config/defaults.rs
use crate::config::app::{Features, Keys, Paths};

pub const DEFAULT_VAULT_KEY: &str = "dev-vault-master-password-2025";
pub const DEFAULT_INDEX_KEY: &str = "dev-index-password-2025";

pub fn default_keys() -> Keys {
    Keys {
        vault_key: DEFAULT_VAULT_KEY.into(),
        index_key: DEFAULT_INDEX_KEY.into(),
    }
}

pub fn default_paths() -> Paths {
    Paths {
        vault_db: "tests/data/vault.db".into(),
        index_db: "tests/data/index.db".into(),
    }
}

pub fn default_features() -> Features {
    Features {
        use_dev_keys: true,
        skip_kdf_slowdown: true,
        allow_insecure_export: true,
    }
}
