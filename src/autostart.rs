use std::path::PathBuf;
use tracing::{info, warn};

fn desktop_file_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("autostart/awg-tray.desktop"))
}

fn desktop_entry() -> String {
    let exec = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "awg-tray".into());

    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=AWG Tray\n\
         Exec={exec}\n\
         Icon=network-vpn\n\
         Terminal=false\n"
    )
}

pub fn is_enabled() -> bool {
    desktop_file_path().is_some_and(|p| p.exists())
}

pub fn enable() {
    let Some(path) = desktop_file_path() else {
        warn!("Cannot determine autostart directory");
        return;
    };

    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            warn!("Failed to create autostart directory: {e}");
            return;
        }
    }

    match std::fs::write(&path, desktop_entry()) {
        Ok(()) => info!("Created autostart entry: {}", path.display()),
        Err(e) => warn!("Failed to write autostart file: {e}"),
    }
}

pub fn disable() {
    let Some(path) = desktop_file_path() else {
        return;
    };

    match std::fs::remove_file(&path) {
        Ok(()) => info!("Removed autostart entry: {}", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!("Failed to remove autostart file: {e}"),
    }
}

pub fn toggle() {
    if is_enabled() {
        disable();
    } else {
        enable();
    }
}
