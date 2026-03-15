# AWG Tray

System tray manager for [AmneziaWireGuard](https://amnezia.org/) VPN connections.

- See VPN status at a glance via the tray icon
- Connect, disconnect, and switch between servers
- Auto-discovers `.conf` files in your config directory
- Optional autostart at login

## NixOS Setup

Add the following to your `configuration.nix`:

```nix
# System tray support (required for AWG Tray)
environment.systemPackages = with pkgs; [
  gnomeExtensions.appindicator
];

services.udev.packages = with pkgs; [ gnome-settings-daemon ];

# Passwordless sudo for awg-quick (replace "user" with your username)
security.sudo.extraRules = [{
  users = [ "user" ];
  commands = [{
    command = "/run/current-system/sw/bin/awg-quick";
    options = [ "NOPASSWD" ];
  }];
}];
```

Rebuild:

```sh
sudo nixos-rebuild switch
```

Then enable the extension (the `gnome-extensions enable` command won't work for system-level extensions on NixOS):

```sh
gsettings set org.gnome.shell enabled-extensions "['appindicatorsupport@rgcjonas.gmail.com']"
```

Or declaratively in `configuration.nix`:

```nix
# If using home-manager
dconf.settings."org/gnome/shell".enabled-extensions = [
  "appindicatorsupport@rgcjonas.gmail.com"
];
```

## Installation

Install system-wide with Nix:

```sh
nix profile install .
```

Or add to your `configuration.nix` as a flake input:

```nix
# In your flake inputs:
awg-tray.url = "github:YOUR_USER/awg-tray";  # or "path:/home/user/dev/vpn"

# In your system config:
environment.systemPackages = [ inputs.awg-tray.packages.${system}.default ];
```

## Building from Source

```sh
nix build .              # Nix (output in ./result/bin/awg-tray)
nix develop && cargo build --release  # Cargo (output in target/release/awg-tray)
```

## Usage

```sh
# Uses default config directory ~/dev/vpn
awg-tray

# Custom config directory
awg-tray --config-dir /path/to/configs
```

Place your AmneziaWireGuard `.conf` files in the config directory. Each file becomes a server entry in the tray menu (e.g. `latvia.conf` → "Latvia").

## Configuration

Optional config file at `~/.config/awg-tray/config.toml`:

```toml
config_dir = "/home/user/dev/vpn"
poll_interval_secs = 5
```

CLI flags override the config file.

## How It Works

- **Status detection**: polls `ip link show <interface>` every 5 seconds
- **Privilege escalation**: uses passwordless `sudo` for `awg-quick` (requires sudoers rule)
- **Tray protocol**: StatusNotifierItem via D-Bus (requires the GNOME AppIndicator extension)
