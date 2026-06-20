use std::path::PathBuf;

use ksni::menu::*;
use tokio::sync::mpsc;

use crate::autostart;
use crate::icon;
use crate::vpn::VpnStatus;

/// Actions sent from tray menu callbacks to the async handler.
#[derive(Debug)]
pub enum VpnAction {
    Connect(String),
    Disconnect,
    ToggleAutostart,
    Quit,
}

pub struct VpnTray {
    pub status: VpnStatus,
    pub autostart: bool,
    pub config_dir: PathBuf,
    pub action_tx: mpsc::UnboundedSender<VpnAction>,
}

impl ksni::Tray for VpnTray {
    fn id(&self) -> String {
        "awg-tray".into()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![icon::status_icon(&self.status)]
    }

    fn title(&self) -> String {
        "AWG Tray".into()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: self.status.label(),
            ..Default::default()
        }
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        // Re-scan configs each time menu is opened
        let servers = crate::vpn::discover_servers(&self.config_dir);

        let mut items: Vec<ksni::MenuItem<Self>> = Vec::new();

        // Status label (non-interactive)
        items.push(
            StandardItem {
                label: format!("Status: {}", self.status.label()),
                enabled: false,
                ..Default::default()
            }
            .into(),
        );

        items.push(ksni::MenuItem::Separator);

        // Server radio group
        let active = self.status.active_server();
        let selected = servers
            .iter()
            .position(|s| active.is_some_and(|a| a == s.name))
            .unwrap_or(usize::MAX);

        let options: Vec<RadioItem> = servers
            .iter()
            .map(|s| {
                let mut label = {
                    let mut chars = s.name.chars();
                    match chars.next() {
                        Some(c) => c.to_uppercase().to_string() + chars.as_str(),
                        None => s.name.clone(),
                    }
                };
                if s.kind == crate::vpn::ServerKind::Vless {
                    label.push_str(" (VLESS)");
                }
                RadioItem {
                    label,
                    ..Default::default()
                }
            })
            .collect();

        // Capture server names for the closure
        let server_names: Vec<String> = servers.iter().map(|s| s.name.clone()).collect();

        items.push(
            RadioGroup {
                selected,
                select: Box::new(move |tray: &mut Self, idx| {
                    if let Some(name) = server_names.get(idx) {
                        let _ = tray.action_tx.send(VpnAction::Connect(name.clone()));
                    }
                }),
                options,
                ..Default::default()
            }
            .into(),
        );

        items.push(ksni::MenuItem::Separator);

        // Disconnect (only when connected)
        if matches!(self.status, VpnStatus::Connected(_)) {
            items.push(
                StandardItem {
                    label: "Disconnect".into(),
                    activate: Box::new(|tray: &mut Self| {
                        let _ = tray.action_tx.send(VpnAction::Disconnect);
                    }),
                    ..Default::default()
                }
                .into(),
            );
            items.push(ksni::MenuItem::Separator);
        }

        // Autostart checkbox
        items.push(
            CheckmarkItem {
                label: "Autostart".into(),
                checked: autostart::is_enabled(),
                activate: Box::new(|tray: &mut Self| {
                    let _ = tray.action_tx.send(VpnAction::ToggleAutostart);
                }),
                ..Default::default()
            }
            .into(),
        );

        // Quit
        items.push(
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(|tray: &mut Self| {
                    let _ = tray.action_tx.send(VpnAction::Quit);
                }),
                ..Default::default()
            }
            .into(),
        );

        items
    }
}
