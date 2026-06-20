//! Throwaway helper: prints the sing-box config generated for a vless link.
//!
//! Usage:
//!   cargo run --example dump_config -- 'vless://…'            # full TUN config
//!   cargo run --example dump_config -- --socks 'vless://…'    # SOCKS test config
#[path = "../src/vless.rs"]
mod vless;

fn main() {
    let mut args = std::env::args().skip(1);
    let first = args.next().expect("pass a vless:// link");
    let (socks, link) = if first == "--socks" {
        (true, args.next().expect("pass a vless:// link"))
    } else {
        (false, first)
    };

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
        parsed.to_singbox_config("tun-vless", ip.as_deref())
    };
    println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
}
