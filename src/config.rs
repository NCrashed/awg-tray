use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::warn;

#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub config_dir: PathBuf,
    pub poll_interval_secs: u64,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            config_dir: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("/home"))
                .join("dev/vpn"),
            poll_interval_secs: 5,
        }
    }
}

impl AppConfig {
    /// Load config from `~/.config/awg-tray/config.toml`, falling back to defaults.
    pub fn load() -> Self {
        let Some(config_dir) = dirs::config_dir() else {
            return Self::default();
        };
        let path = config_dir.join("awg-tray/config.toml");
        Self::load_from(&path)
    }

    fn load_from(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(contents) => match toml::from_str(&contents) {
                Ok(config) => config,
                Err(e) => {
                    warn!("Invalid config at {}: {e}, using defaults", path.display());
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }
}
