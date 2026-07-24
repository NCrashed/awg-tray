//! Throwaway helper: prints the sing-box config generated for a vless link.
//!
//! Usage:
//!   cargo run --example dump_config -- 'vless://…'            # full TUN config
//!   cargo run --example dump_config -- --socks 'vless://…'    # SOCKS test config
//!   cargo run --example dump_config -- --bypass steam,steamwebhelper 'vless://…'
#[path = "../src/vless.rs"]
mod vless;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut socks = false;
    let mut bypass: Vec<String> = Vec::new();
    let mut link = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socks" => socks = true,
            "--bypass" => {
                let list = args.next().expect("--bypass needs a comma-separated list");
                bypass.extend(list.split(',').map(str::to_string));
            }
            _ => link = Some(arg),
        }
    }
    let link = link.expect("pass a vless:// link");

    let parsed = vless::VlessLink::parse(&link).expect("parse");
    let cfg = if socks {
        parsed.to_socks_test_config(1080)
    } else {
        // Resolve the server like the real tool does, so the printed config
        // (incl. route_exclude_address) matches what awg-tray generates.
        use std::net::ToSocketAddrs;
        let ip = (parsed.host.as_str(), parsed.port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut it| it.find(|a| a.is_ipv4()).or_else(|| it.next()))
            .map(|a| a.ip().to_string());
        parsed.to_singbox_config("tun-vless", ip.as_deref(), &bypass)
    };
    println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
}
