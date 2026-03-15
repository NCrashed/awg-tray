use std::path::{Path, PathBuf};
use tokio::process::Command;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnStatus {
    Disconnected,
    Connected(String),
    Connecting(String),
}

impl VpnStatus {
    pub fn label(&self) -> String {
        match self {
            VpnStatus::Disconnected => "Disconnected".into(),
            VpnStatus::Connected(name) => format!("Connected ({name})"),
            VpnStatus::Connecting(name) => format!("Connecting ({name})…"),
        }
    }

    pub fn active_server(&self) -> Option<&str> {
        match self {
            VpnStatus::Connected(name) | VpnStatus::Connecting(name) => Some(name),
            VpnStatus::Disconnected => None,
        }
    }
}

/// Discover .conf files in the config directory, returning (stem, full_path) pairs.
pub fn discover_configs(config_dir: &Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(config_dir) else {
        warn!("Cannot read config directory: {}", config_dir.display());
        return Vec::new();
    };

    let mut configs: Vec<(String, PathBuf)> = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext == "conf")
        })
        .map(|e| {
            let path = e.path();
            let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
            (stem, path)
        })
        .collect();

    configs.sort_by(|a, b| a.0.cmp(&b.0));
    configs
}

/// Check which VPN interface is currently up by probing `ip link show <iface>`.
pub async fn detect_status(config_dir: &Path) -> VpnStatus {
    let configs = discover_configs(config_dir);

    for (name, _path) in &configs {
        match Command::new("ip")
            .args(["link", "show", name])
            .output()
            .await
        {
            Ok(output) if output.status.success() => {
                debug!("Interface {name} is up");
                return VpnStatus::Connected(name.clone());
            }
            Ok(_) => {
                debug!("Interface {name} is not up");
            }
            Err(e) => {
                error!("Failed to run `ip link show {name}`: {e}");
            }
        }
    }

    VpnStatus::Disconnected
}

async fn run_awg_quick(action: &str, config_path: &Path) -> Result<(), String> {
    let path_str = config_path.to_string_lossy();
    info!("{action}: awg-quick {action} {path_str}");

    let output = Command::new("sudo")
        .args(["awg-quick", action, &path_str])
        .output()
        .await
        .map_err(|e| format!("Failed to spawn sudo: {e}"))?;

    if output.status.success() {
        info!("{action} completed successfully");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "awg-quick {action} failed (exit {}): {stderr}",
            output.status.code().unwrap_or(-1)
        ))
    }
}

pub async fn connect(config_path: &Path) -> Result<(), String> {
    run_awg_quick("up", config_path).await
}

pub async fn disconnect(config_path: &Path) -> Result<(), String> {
    run_awg_quick("down", config_path).await
}