mod autostart;
mod config;
mod icon;
mod tray;
mod vless;
mod vpn;

use std::path::PathBuf;

use clap::Parser;
use ksni::TrayMethods;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use config::AppConfig;
use tray::{VpnAction, VpnTray};
use vpn::VpnStatus;

const TRAY_MAX_RETRIES: u32 = 10;
const TRAY_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Parser)]
#[command(name = "awg-tray", about = "AmneziaWireGuard system tray manager")]
struct Cli {
    /// Path to directory containing .conf files
    #[arg(long)]
    config_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let app_config = AppConfig::load();

    let config_dir = cli.config_dir.unwrap_or(app_config.config_dir);
    let poll_interval = std::time::Duration::from_secs(app_config.poll_interval_secs);

    info!("Config directory: {}", config_dir.display());
    info!("Poll interval: {poll_interval:?}");

    if !config_dir.is_dir() {
        error!("Config directory does not exist: {}", config_dir.display());
        std::process::exit(1);
    }

    if vpn::discover_servers(&config_dir).is_empty() {
        warn!("No .conf or .vless files found in {}", config_dir.display());
    }

    let (action_tx, action_rx) = mpsc::unbounded_channel();

    let handle = spawn_tray_with_retry(&config_dir, &action_tx).await;
    info!("Tray spawned successfully");

    // Spawn the action handler
    let action_handle = handle.clone();
    let action_config_dir = config_dir.clone();
    tokio::spawn(handle_actions(action_rx, action_handle, action_config_dir));

    // Spawn the status poller
    let poll_handle = handle.clone();
    let poll_config_dir = config_dir.clone();
    tokio::spawn(poll_status(poll_handle, poll_config_dir, poll_interval));

    // Keep running until Quit action calls process::exit
    std::future::pending::<()>().await;
}

fn build_tray(
    config_dir: &PathBuf,
    action_tx: &mpsc::UnboundedSender<VpnAction>,
    status: VpnStatus,
) -> VpnTray {
    VpnTray {
        status,
        autostart: autostart::is_enabled(),
        config_dir: config_dir.clone(),
        action_tx: action_tx.clone(),
    }
}

async fn spawn_tray_with_retry(
    config_dir: &PathBuf,
    action_tx: &mpsc::UnboundedSender<VpnAction>,
) -> ksni::Handle<VpnTray> {
    let status = vpn::detect_status(config_dir).await;
    info!("Initial status: {}", status.label());

    let tray = build_tray(config_dir, action_tx, status);
    match tray.spawn().await {
        Ok(h) => return h,
        Err(e) => {
            warn!(
                "Failed to spawn tray: {e}. \
                 Retrying every {}s (the SNI watcher may not be ready yet)…",
                TRAY_RETRY_DELAY.as_secs()
            );
        }
    }

    for attempt in 1..=TRAY_MAX_RETRIES {
        tokio::time::sleep(TRAY_RETRY_DELAY).await;
        info!("Retry {attempt}/{TRAY_MAX_RETRIES}…");

        let status = vpn::detect_status(config_dir).await;
        let tray = build_tray(config_dir, action_tx, status);
        match tray.spawn().await {
            Ok(h) => return h,
            Err(e) => {
                warn!("Attempt {attempt} failed: {e}");
            }
        }
    }

    error!(
        "Could not connect to StatusNotifierWatcher after {} attempts. \
         Is the AppIndicator/KStatusNotifierItem GNOME extension installed and enabled?",
        TRAY_MAX_RETRIES
    );
    std::process::exit(1);
}

async fn handle_actions(
    mut rx: mpsc::UnboundedReceiver<VpnAction>,
    handle: ksni::Handle<VpnTray>,
    config_dir: PathBuf,
) {
    while let Some(action) = rx.recv().await {
        match action {
            VpnAction::Connect(server) => {
                // Check current state
                let current = handle
                    .update(|tray| tray.status.active_server().map(String::from))
                    .await
                    .flatten();

                // If already connected to this server, skip
                if current.as_deref() == Some(server.as_str()) {
                    continue;
                }

                // Set connecting state
                let server_clone = server.clone();
                handle
                    .update(move |tray| {
                        tray.status = VpnStatus::Connecting(server_clone);
                    })
                    .await;

                // Disconnect current if any
                if let Some(current_server) = &current {
                    match vpn::find_server(&config_dir, current_server) {
                        Some(srv) => {
                            if let Err(e) = vpn::disconnect(&srv).await {
                                warn!("Failed to disconnect {current_server}: {e}");
                                let prev = current_server.clone();
                                handle
                                    .update(move |tray| {
                                        tray.status = VpnStatus::Connected(prev);
                                    })
                                    .await;
                                continue;
                            }
                        }
                        None => warn!(
                            "Active server {current_server} no longer exists; skipping disconnect"
                        ),
                    }
                }

                // Connect to new server
                let Some(target) = vpn::find_server(&config_dir, &server) else {
                    warn!("Server {server} not found");
                    handle
                        .update(|tray| {
                            tray.status = VpnStatus::Disconnected;
                        })
                        .await;
                    continue;
                };
                match vpn::connect(&target).await {
                    Ok(()) => {
                        let s = server.clone();
                        handle
                            .update(move |tray| {
                                tray.status = VpnStatus::Connected(s);
                            })
                            .await;
                    }
                    Err(e) => {
                        warn!("Failed to connect to {server}: {e}");
                        handle
                            .update(|tray| {
                                tray.status = VpnStatus::Disconnected;
                            })
                            .await;
                    }
                }
            }

            VpnAction::Disconnect => {
                let current = handle
                    .update(|tray| tray.status.active_server().map(String::from))
                    .await
                    .flatten();

                if let Some(server) = current {
                    let Some(target) = vpn::find_server(&config_dir, &server) else {
                        warn!("Server {server} not found; cannot disconnect");
                        continue;
                    };
                    match vpn::disconnect(&target).await {
                        Ok(()) => {
                            handle
                                .update(|tray| {
                                    tray.status = VpnStatus::Disconnected;
                                })
                                .await;
                        }
                        Err(e) => {
                            warn!("Failed to disconnect: {e}");
                        }
                    }
                }
            }

            VpnAction::ToggleAutostart => {
                autostart::toggle();
                let enabled = autostart::is_enabled();
                handle
                    .update(move |tray| {
                        tray.autostart = enabled;
                    })
                    .await;
            }

            VpnAction::Quit => {
                info!("Quit requested");
                std::process::exit(0);
            }
        }
    }
}

async fn poll_status(
    handle: ksni::Handle<VpnTray>,
    config_dir: PathBuf,
    interval: std::time::Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // skip first immediate tick

    loop {
        ticker.tick().await;

        let new_status = vpn::detect_status(&config_dir).await;

        handle
            .update(|tray| {
                if matches!(tray.status, VpnStatus::Connecting(_)) {
                    return; // don't override transitional state
                }
                if tray.status != new_status {
                    info!(
                        "Status changed: {} → {}",
                        tray.status.label(),
                        new_status.label()
                    );
                    tray.status = new_status;
                }
            })
            .await;
    }
}
