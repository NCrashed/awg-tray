use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::warn;

/// An application whose traffic can bypass the tunnel (VLESS mode only).
/// Matched by executable name via sing-box `process_name` route rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BypassApp {
    /// Label shown in the tray menu.
    pub name: String,
    /// Executable names as the kernel sees them (e.g. `steam`, `qbittorrent`).
    pub processes: Vec<String>,
    /// Whether this app's traffic currently goes direct, outside the tunnel.
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_config_dir")]
    pub config_dir: PathBuf,
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,
    /// Apps that may be routed around the tunnel; toggled from the tray menu.
    #[serde(default = "default_bypass_apps")]
    pub bypass_apps: Vec<BypassApp>,
}

fn default_config_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/home"))
        .join("dev/vpn")
}

fn default_poll_interval_secs() -> u64 {
    5
}

fn default_bypass_apps() -> Vec<BypassApp> {
    let app = |name: &str, processes: &[&str]| BypassApp {
        name: name.to_string(),
        processes: processes.iter().map(|s| s.to_string()).collect(),
        enabled: false,
    };
    vec![
        app("Steam", &["steam", "steamwebhelper"]),
        app("qBittorrent", &["qbittorrent", "qbittorrent-nox"]),
        app(
            "Transmission",
            &[
                "transmission-gtk",
                "transmission-qt",
                "transmission-daemon",
                "transmission-cli",
            ],
        ),
    ]
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            config_dir: default_config_dir(),
            poll_interval_secs: default_poll_interval_secs(),
            bypass_apps: default_bypass_apps(),
        }
    }
}

impl AppConfig {
    /// Path of the config file: `~/.config/awg-tray/config.toml`.
    fn path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("awg-tray/config.toml"))
    }

    /// Load config from `~/.config/awg-tray/config.toml`, falling back to defaults.
    pub fn load() -> Self {
        let Some(path) = Self::path() else {
            return Self::default();
        };
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

    /// Persist the config (used to remember bypass toggles across restarts).
    pub fn save(&self) -> Result<(), String> {
        let path = Self::path().ok_or_else(|| "no config directory".to_string())?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
        }
        let contents =
            toml::to_string_pretty(self).map_err(|e| format!("Failed to serialize config: {e}"))?;
        std::fs::write(&path, contents)
            .map_err(|e| format!("Failed to write {}: {e}", path.display()))
    }

    /// Flip an app's bypass state by name. Returns `false` if no such app.
    pub fn toggle_bypass(&mut self, name: &str) -> bool {
        match self.bypass_apps.iter_mut().find(|a| a.name == name) {
            Some(app) => {
                app.enabled = !app.enabled;
                true
            }
            None => false,
        }
    }

    /// Process names of every enabled bypass app, for the sing-box route rule.
    pub fn enabled_bypass_processes(&self) -> Vec<String> {
        self.bypass_apps
            .iter()
            .filter(|a| a.enabled)
            .flat_map(|a| a.processes.iter().cloned())
            .collect()
    }
}
