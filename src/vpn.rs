use std::path::{Path, PathBuf};
use tokio::process::Command;
use tracing::{debug, error, info, warn};

use crate::vless::VlessLink;

/// Fixed TUN interface name used by the sing-box VLESS backend. Kept short to
/// satisfy the 15-char Linux interface name limit (IFNAMSIZ).
const VLESS_TUN: &str = "tun-vless";

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

/// Backend used to bring a server up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerKind {
    /// AmneziaWireGuard `.conf`, managed by `awg-quick`.
    Wireguard,
    /// VLESS `.vless` share link, managed by `sing-box` in a TUN.
    Vless,
}

/// A discovered VPN server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub name: String,
    pub path: PathBuf,
    pub kind: ServerKind,
}

/// Discover `.conf` (WireGuard) and `.vless` (VLESS) files in the config
/// directory, sorted by name. The file stem becomes the server name.
pub fn discover_servers(config_dir: &Path) -> Vec<Server> {
    let Ok(entries) = std::fs::read_dir(config_dir) else {
        warn!("Cannot read config directory: {}", config_dir.display());
        return Vec::new();
    };

    let mut servers: Vec<Server> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let path = e.path();
            let kind = match path.extension().and_then(|x| x.to_str()) {
                Some("conf") => ServerKind::Wireguard,
                Some("vless") => ServerKind::Vless,
                _ => return None,
            };
            let name = path.file_stem()?.to_string_lossy().into_owned();
            Some(Server { name, path, kind })
        })
        .collect();

    servers.sort_by(|a, b| a.name.cmp(&b.name));
    servers
}

/// Look up a single server by name.
pub fn find_server(config_dir: &Path, name: &str) -> Option<Server> {
    discover_servers(config_dir)
        .into_iter()
        .find(|s| s.name == name)
}

/// Determine which server (if any) is currently active.
pub async fn detect_status(config_dir: &Path) -> VpnStatus {
    for server in discover_servers(config_dir) {
        let up = match server.kind {
            ServerKind::Wireguard => wireguard_is_up(&server.name).await,
            ServerKind::Vless => vless_is_up(&server.name).await,
        };
        if up {
            debug!("{} is up", server.name);
            return VpnStatus::Connected(server.name);
        }
    }
    VpnStatus::Disconnected
}

/// A WireGuard interface is up if a network interface with its name exists.
async fn wireguard_is_up(name: &str) -> bool {
    match Command::new("ip")
        .args(["link", "show", name])
        .output()
        .await
    {
        Ok(output) => output.status.success(),
        Err(e) => {
            error!("Failed to run `ip link show {name}`: {e}");
            false
        }
    }
}

/// A VLESS server is up if its transient sing-box systemd unit is active.
async fn vless_is_up(name: &str) -> bool {
    match Command::new("systemctl")
        .args(["is-active", "--quiet", &vless_unit(name)])
        .status()
        .await
    {
        Ok(status) => status.success(),
        Err(e) => {
            error!("Failed to query systemd unit for {name}: {e}");
            false
        }
    }
}

pub async fn connect(server: &Server) -> Result<(), String> {
    match server.kind {
        ServerKind::Wireguard => run_awg_quick("up", &server.path).await,
        ServerKind::Vless => vless_connect(server).await,
    }
}

pub async fn disconnect(server: &Server) -> Result<(), String> {
    match server.kind {
        ServerKind::Wireguard => run_awg_quick("down", &server.path).await,
        ServerKind::Vless => vless_disconnect(server).await,
    }
}

// ---------------------------------------------------------------------------
// WireGuard backend
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// VLESS backend (sing-box in a transient systemd unit)
// ---------------------------------------------------------------------------

/// systemd unit name for a VLESS server. Sanitised to the chars systemd allows.
fn vless_unit(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("awg-vless-{sanitized}")
}

/// Resolve a host to an IP string (preferring IPv4). Returns `None` if it
/// cannot be resolved, in which case the caller falls back to the hostname.
async fn resolve_host(host: &str, port: u16) -> Option<String> {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Some(host.to_string());
    }
    match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => {
            let addrs: Vec<std::net::SocketAddr> = addrs.collect();
            let chosen = addrs
                .iter()
                .find(|a| a.is_ipv4())
                .or_else(|| addrs.first())
                .map(|a| a.ip().to_string());
            match &chosen {
                Some(ip) => info!("Resolved {host} -> {ip}"),
                None => warn!("No addresses for {host}; using hostname"),
            }
            chosen
        }
        Err(e) => {
            warn!("Could not resolve {host}: {e}; using hostname");
            None
        }
    }
}

/// Directory holding generated sing-box configs (user-private, 0700).
fn vless_runtime_dir() -> PathBuf {
    dirs::runtime_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("awg-tray")
}

async fn vless_connect(server: &Server) -> Result<(), String> {
    let raw = tokio::fs::read_to_string(&server.path)
        .await
        .map_err(|e| format!("Failed to read {}: {e}", server.path.display()))?;
    let link = VlessLink::parse(&raw).map_err(|e| format!("Invalid vless link: {e}"))?;

    // Resolve the server hostname now, before the TUN is up — resolving it
    // afterwards deadlocks against the tunnel's DNS hijack.
    let server_ip = resolve_host(&link.host, link.port).await;
    let config = link.to_singbox_config(VLESS_TUN, server_ip.as_deref());
    let json = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize sing-box config: {e}"))?;

    let dir = vless_runtime_dir();
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| format!("Failed to create {}: {e}", dir.display()))?;
    restrict_permissions(&dir).await;

    let cfg_path = dir.join(format!("{}.json", server.name));
    tokio::fs::write(&cfg_path, json)
        .await
        .map_err(|e| format!("Failed to write {}: {e}", cfg_path.display()))?;

    let unit = vless_unit(&server.name);
    let cfg_str = cfg_path.to_string_lossy();
    info!("up: systemd-run --unit {unit} sing-box run -c {cfg_str}");

    // Run sing-box as a transient system unit so the tunnel survives even if the
    // tray exits — matching the persistence of a kernel WireGuard interface.
    let output = Command::new("sudo")
        .args([
            "systemd-run",
            &format!("--unit={unit}"),
            "--collect",
            "--property=Restart=on-failure",
            "sing-box",
            "run",
            "-c",
            &cfg_str,
        ])
        .output()
        .await
        .map_err(|e| format!("Failed to spawn sudo systemd-run: {e}"))?;

    if output.status.success() {
        info!("VLESS unit {unit} started");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "systemd-run failed (exit {}): {stderr}",
            output.status.code().unwrap_or(-1)
        ))
    }
}

async fn vless_disconnect(server: &Server) -> Result<(), String> {
    let unit = vless_unit(&server.name);
    info!("down: systemctl stop {unit}");

    let output = Command::new("sudo")
        .args(["systemctl", "stop", &unit])
        .output()
        .await
        .map_err(|e| format!("Failed to spawn sudo systemctl: {e}"))?;

    if output.status.success() {
        info!("VLESS unit {unit} stopped");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "systemctl stop failed (exit {}): {stderr}",
            output.status.code().unwrap_or(-1)
        ))
    }
}

/// Best-effort tighten of the runtime dir to 0700 (it may hold the uuid).
async fn restrict_permissions(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await
        {
            debug!("Could not set permissions on {}: {e}", dir.display());
        }
    }
}
