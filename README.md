# AWG Tray

System tray manager for [AmneziaWireGuard](https://amnezia.org/) and
[VLESS](https://xtls.github.io/) VPN connections.

- See VPN status at a glance via the tray icon
- Connect, disconnect, and switch between servers
- Auto-discovers `.conf` (WireGuard) and `.vless` (VLESS) files in your config directory
- VLESS support (incl. Reality + `xtls-rprx-vision`) via [sing-box](https://sing-box.sagernet.org/) in a full-tunnel TUN
- Optional autostart at login

## NixOS Setup

Add the following to your `configuration.nix`:

```nix
# System tray support (required for AWG Tray)
environment.systemPackages = with pkgs; [
  gnomeExtensions.appindicator
  sing-box  # required for VLESS servers (.vless files); >= 1.12
];

services.udev.packages = with pkgs; [ gnome-settings-daemon ];

# Passwordless sudo for awg-quick (WireGuard) and the VLESS backend.
# Replace "user" with your username.
security.sudo.extraRules = [{
  users = [ "user" ];
  commands = [
    { command = "/run/current-system/sw/bin/awg-quick"; options = [ "NOPASSWD" ]; }
    # VLESS: start sing-box in a transient unit and stop it again.
    { command = "/run/current-system/sw/bin/systemd-run"; options = [ "NOPASSWD" ]; }
    { command = "/run/current-system/sw/bin/systemctl"; options = [ "NOPASSWD" ]; }
  ];
}];
```

> `sing-box` only needs to be installed if you use VLESS servers. WireGuard-only
> setups can omit it and the two extra sudo rules.

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

Place your server files in the config directory. Each file becomes a server entry
in the tray menu:

- **WireGuard** — AmneziaWireGuard `.conf` files (e.g. `latvia.conf` → "Latvia").
- **VLESS** — `.vless` files, each containing a single `vless://…` share link.
  The file name is the menu label (e.g. `Poland.vless` → "Poland (VLESS)"); the
  `#fragment` of the link is ignored for naming. Supports `tcp`/`ws`/`grpc`
  transports and `tls`/`reality` security (including `xtls-rprx-vision` flow).

Example `Poland.vless`:

```
vless://UUID@host.example:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=cdn.example&fp=firefox&pbk=PUBKEY&sid=SHORTID#MyLabel
```

Switching servers automatically tears the current one down first, so WireGuard
and VLESS servers are mutually exclusive — exactly one tunnel is ever active.

## Configuration

Optional config file at `~/.config/awg-tray/config.toml`:

```toml
config_dir = "/home/user/dev/vpn"
poll_interval_secs = 5
```

CLI flags override the config file.

## How It Works

- **WireGuard servers** (`.conf`): brought up/down with `sudo awg-quick up/down`.
  Status is detected by polling `ip link show <interface>`.
- **VLESS servers** (`.vless`): the share link is parsed into a sing-box config
  (written to `$XDG_RUNTIME_DIR/awg-tray/<name>.json`, mode 0700) which is run as
  a transient systemd unit `awg-vless-<name>` via `sudo systemd-run`. It creates a
  full-tunnel TUN interface (`tun-vless`), so all traffic is routed like WireGuard.
  Disconnect runs `sudo systemctl stop awg-vless-<name>`; status is detected with
  `systemctl is-active`. Running it as a transient unit means the tunnel survives
  even if the tray exits, matching kernel WireGuard's persistence.
- **VLESS server reachability**: the generated config dials the server by its
  pre-resolved IP and excludes that IP from the TUN (`route_exclude_address`) so
  the proxy's own connection escapes the tunnel instead of looping back in.
- **Status detection**: polls every 5 seconds (configurable)
- **Privilege escalation**: passwordless `sudo` for `awg-quick` / `systemd-run` /
  `systemctl` (requires sudoers rules — see NixOS Setup)
- **Tray protocol**: StatusNotifierItem via D-Bus (requires the GNOME AppIndicator extension)

## Troubleshooting VLESS

Tail the tunnel logs:

```sh
journalctl -u awg-vless-<name> -f
```

- **Shows "connected" but no traffic, logs say `dial tcp <server-ip>:443: i/o
  timeout`**: the tunnel is up but it cannot reach the VLESS server. Test the
  server directly (with no VPN active):

  ```sh
  # does TCP connect at all?
  nc -vz <server-ip> 443
  # does the TLS handshake complete? (watch for "Server hello")
  curl -vsk --resolve <sni>:443:<server-ip> https://<sni>/ -o /dev/null
  ```

  If TCP connects but the TLS handshake never returns a *Server hello* — even for
  an unrelated SNI like `www.microsoft.com` — your ISP is **IP-blocking the
  server** at the TLS layer. No client setting (fingerprint, SNI, fragmentation)
  can bypass that; ask your provider for a different server endpoint and drop in a
  new `.vless` file.
- **`lookup <host>: context deadline exceeded`**: the server hostname could not
  be pre-resolved before the tunnel came up. Check your system DNS works without
  the VPN.
