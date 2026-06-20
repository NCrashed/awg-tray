//! Parsing of `vless://` share links and generation of sing-box configs.
//!
//! A VLESS connection is terminated by a userspace core (sing-box) running a
//! TUN inbound, so it behaves like a full-tunnel VPN just like the WireGuard
//! `.conf` files — all traffic is routed through it.

use std::collections::HashMap;

use serde_json::{json, Value};

/// A parsed `vless://` share link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessLink {
    pub uuid: String,
    pub host: String,
    pub port: u16,
    /// Fragment after `#`, the human-readable label (e.g. `RedShieldVPN_Poland`).
    pub label: Option<String>,
    /// Transport: `tcp` (default), `ws`, `grpc`.
    pub transport: String,
    /// Security layer: `none` (default), `tls`, `reality`.
    pub security: String,
    pub flow: Option<String>,
    pub sni: Option<String>,
    /// uTLS fingerprint (`fp`), e.g. `firefox`, `chrome`.
    pub fingerprint: Option<String>,
    /// Reality public key (`pbk`).
    pub public_key: Option<String>,
    /// Reality short id (`sid`).
    pub short_id: Option<String>,
    /// ws/http path (`path`).
    pub path: Option<String>,
    /// ws `Host` header (`host`).
    pub host_header: Option<String>,
    /// gRPC service name (`serviceName`).
    pub service_name: Option<String>,
    /// Comma-separated ALPN list (`alpn`).
    pub alpn: Option<String>,
}

impl VlessLink {
    /// Parse a `vless://uuid@host:port?params#label` link.
    pub fn parse(link: &str) -> Result<Self, String> {
        let link = link.trim();
        let rest = link
            .strip_prefix("vless://")
            .ok_or_else(|| "not a vless:// link".to_string())?;

        // Split off the fragment (#label) first.
        let (rest, label) = match rest.split_once('#') {
            Some((r, frag)) => (r, Some(percent_decode(frag))),
            None => (rest, None),
        };

        // Split userinfo+host from the query string.
        let (authority, query) = match rest.split_once('?') {
            Some((a, q)) => (a, q),
            None => (rest, ""),
        };

        // userinfo@host:port
        let (uuid, hostport) = authority
            .split_once('@')
            .ok_or_else(|| "missing '@' separating uuid from host".to_string())?;
        if uuid.is_empty() {
            return Err("empty uuid".to_string());
        }

        let (host, port) = split_host_port(hostport)?;

        let params = parse_query(query);

        let get = |k: &str| params.get(k).filter(|v| !v.is_empty()).cloned();

        Ok(VlessLink {
            uuid: uuid.to_string(),
            host,
            port,
            label,
            transport: get("type").unwrap_or_else(|| "tcp".to_string()),
            security: get("security").unwrap_or_else(|| "none".to_string()),
            flow: get("flow"),
            sni: get("sni"),
            fingerprint: get("fp"),
            public_key: get("pbk"),
            short_id: get("sid"),
            path: get("path"),
            host_header: get("host"),
            service_name: get("serviceName"),
            alpn: get("alpn"),
        })
    }

    /// Build the VLESS proxy outbound object (tagged `proxy`).
    pub fn outbound(&self) -> Value {
        let mut proxy = json!({
            "type": "vless",
            "tag": "proxy",
            "server": self.host,
            "server_port": self.port,
            "uuid": self.uuid,
            "packet_encoding": "xudp",
        });

        if let Some(flow) = &self.flow {
            proxy["flow"] = json!(flow);
        }

        if self.security != "none" {
            let mut tls = json!({
                "enabled": true,
                "server_name": self.sni.clone().unwrap_or_else(|| self.host.clone()),
            });
            if let Some(fp) = &self.fingerprint {
                tls["utls"] = json!({ "enabled": true, "fingerprint": fp });
            }
            if self.security == "reality" {
                let mut reality = json!({ "enabled": true });
                if let Some(pbk) = &self.public_key {
                    reality["public_key"] = json!(pbk);
                }
                if let Some(sid) = &self.short_id {
                    reality["short_id"] = json!(sid);
                }
                tls["reality"] = reality;
            }
            if let Some(alpn) = &self.alpn {
                let list: Vec<&str> = alpn
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .collect();
                tls["alpn"] = json!(list);
            }
            proxy["tls"] = tls;
        }

        // --- transport ---
        match self.transport.as_str() {
            "ws" => {
                let mut t = json!({ "type": "ws" });
                if let Some(p) = &self.path {
                    t["path"] = json!(p);
                }
                if let Some(h) = &self.host_header {
                    t["headers"] = json!({ "Host": h });
                }
                proxy["transport"] = t;
            }
            "grpc" => {
                let mut t = json!({ "type": "grpc" });
                if let Some(sn) = &self.service_name {
                    t["service_name"] = json!(sn);
                }
                proxy["transport"] = t;
            }
            // "tcp" and anything else: raw TCP, no transport object.
            _ => {}
        }

        proxy
    }

    /// A minimal SOCKS-only config (no TUN, no routing changes) for testing
    /// whether the VLESS connection itself works, isolated from TUN/routing.
    /// Used by the `dump_config` example for diagnostics.
    #[allow(dead_code)]
    pub fn to_socks_test_config(&self, socks_port: u16) -> Value {
        json!({
            "log": { "level": "info", "timestamp": true },
            "inbounds": [
                { "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": socks_port }
            ],
            "outbounds": [
                self.outbound(),
                { "type": "direct", "tag": "direct" }
            ],
            "route": { "final": "proxy" }
        })
    }

    /// Build a sing-box configuration (sing-box >= 1.12 schema) that exposes a
    /// TUN inbound named `tun_iface` and routes everything through this server.
    ///
    /// `server_ip`, when given, replaces the proxy `server` hostname with a
    /// pre-resolved IP. This is important under TUN: resolving the proxy
    /// hostname *after* the tunnel is up deadlocks (the lookup is hijacked back
    /// into sing-box's DNS, which can't answer until the proxy connects).
    pub fn to_singbox_config(&self, tun_iface: &str, server_ip: Option<&str>) -> Value {
        let mut proxy = self.outbound();

        let mut tun = json!({
            "type": "tun",
            "tag": "tun-in",
            "interface_name": tun_iface,
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 1400,
            "auto_route": true,
            // strict_route adds nft rules that can drop the proxy's own egress on
            // systems with their own firewall (e.g. NixOS); keep it off.
            "strict_route": false,
            // gvisor (userspace netstack) reliably forwards TUN traffic to the
            // outbound; the "system" stack silently fails to forward on some
            // Linux setups (traffic enters the TUN but never reaches the proxy).
            "stack": "gvisor"
        });

        if let Some(ip) = server_ip {
            // Connect to the server by its pre-resolved IP (no DNS needed to dial
            // the proxy)...
            proxy["server"] = json!(ip);
            // ...and exclude that IP from the TUN so the kernel routes the proxy's
            // own connection out the physical interface instead of looping it back
            // into the tunnel. Without this the server dial times out.
            let cidr = if ip.contains(':') {
                format!("{ip}/128")
            } else {
                format!("{ip}/32")
            };
            tun["route_exclude_address"] = json!([cidr]);
        }

        json!({
            "log": { "level": "warn", "timestamp": true },
            "dns": {
                // New-style DNS servers (sing-box >= 1.12). User queries go out
                // through the proxy; the proxy's own hostname is resolved locally
                // via `default_domain_resolver` below as a fallback when the IP
                // could not be pre-resolved.
                "servers": [
                    { "type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy" },
                    { "type": "local", "tag": "local" }
                ],
                "strategy": "prefer_ipv4"
            },
            "inbounds": [ tun ],
            "outbounds": [
                proxy,
                { "type": "direct", "tag": "direct" }
            ],
            "route": {
                "rules": [
                    { "action": "sniff" },
                    { "protocol": "dns", "action": "hijack-dns" }
                ],
                "auto_detect_interface": true,
                // Resolve outbound server domains (incl. the proxy host) locally.
                "default_domain_resolver": "local",
                "final": "proxy"
            }
        })
    }
}

/// Split `host:port`, handling bracketed IPv6 literals (`[::1]:443`).
fn split_host_port(hostport: &str) -> Result<(String, u16), String> {
    if let Some(rest) = hostport.strip_prefix('[') {
        // [ipv6]:port
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| "unterminated IPv6 literal".to_string())?;
        let port = after
            .strip_prefix(':')
            .ok_or_else(|| "missing port after IPv6 host".to_string())?;
        let port = port.parse().map_err(|_| format!("invalid port: {port}"))?;
        return Ok((host.to_string(), port));
    }

    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or_else(|| "missing ':port'".to_string())?;
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    let port = port.parse().map_err(|_| format!("invalid port: {port}"))?;
    Ok((host.to_string(), port))
}

/// Parse a `k1=v1&k2=v2` query string, percent-decoding keys and values.
fn parse_query(query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        map.insert(percent_decode(k), percent_decode(v));
    }
    map
}

/// Percent-decode an RFC-3986 component. `+` is left untouched (VLESS links use
/// raw percent-encoding, not form-encoding, and base64 keys may contain `+`).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "vless://bbbf5c14-d37d-484d-a5ae-5dbfd816a869@po.superbhost.xyz:443?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&sni=cdn14.supermegacdn.com&fp=firefox&pbk=PVlnR_I9tZ8hKhOHW6ySpSofhsaShcBQ_JV2-0TePVA&sid=9bde6a1e7b42e680&spx=%2F#RedShieldVPN_Poland";

    #[test]
    fn parses_reality_link() {
        let l = VlessLink::parse(SAMPLE).unwrap();
        assert_eq!(l.uuid, "bbbf5c14-d37d-484d-a5ae-5dbfd816a869");
        assert_eq!(l.host, "po.superbhost.xyz");
        assert_eq!(l.port, 443);
        assert_eq!(l.transport, "tcp");
        assert_eq!(l.security, "reality");
        assert_eq!(l.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(l.sni.as_deref(), Some("cdn14.supermegacdn.com"));
        assert_eq!(l.fingerprint.as_deref(), Some("firefox"));
        assert_eq!(
            l.public_key.as_deref(),
            Some("PVlnR_I9tZ8hKhOHW6ySpSofhsaShcBQ_JV2-0TePVA")
        );
        assert_eq!(l.short_id.as_deref(), Some("9bde6a1e7b42e680"));
        assert_eq!(l.label.as_deref(), Some("RedShieldVPN_Poland"));
    }

    #[test]
    fn builds_singbox_config() {
        let l = VlessLink::parse(SAMPLE).unwrap();
        let cfg = l.to_singbox_config("tun-vless", Some("1.2.3.4"));
        let out = &cfg["outbounds"][0];
        assert_eq!(out["type"], "vless");
        // server is the pre-resolved IP; SNI stays the reality hostname.
        assert_eq!(out["server"], "1.2.3.4");
        assert_eq!(out["server_port"], 443);
        assert_eq!(out["flow"], "xtls-rprx-vision");
        assert_eq!(
            out["tls"]["reality"]["public_key"],
            "PVlnR_I9tZ8hKhOHW6ySpSofhsaShcBQ_JV2-0TePVA"
        );
        assert_eq!(out["tls"]["reality"]["short_id"], "9bde6a1e7b42e680");
        assert_eq!(out["tls"]["server_name"], "cdn14.supermegacdn.com");
        assert_eq!(out["tls"]["utls"]["fingerprint"], "firefox");
        assert_eq!(cfg["inbounds"][0]["interface_name"], "tun-vless");
        // The server IP must be excluded from the TUN to avoid a routing loop.
        assert_eq!(cfg["inbounds"][0]["route_exclude_address"][0], "1.2.3.4/32");
    }

    #[test]
    fn no_exclude_without_resolved_ip() {
        let l = VlessLink::parse(SAMPLE).unwrap();
        let cfg = l.to_singbox_config("tun-vless", None);
        assert_eq!(cfg["outbounds"][0]["server"], "po.superbhost.xyz");
        assert!(cfg["inbounds"][0]["route_exclude_address"].is_null());
    }

    #[test]
    fn rejects_non_vless() {
        assert!(VlessLink::parse("https://example.com").is_err());
    }

    #[test]
    fn parses_ipv6_host() {
        let l = VlessLink::parse("vless://uuid@[2001:db8::1]:8443?type=tcp").unwrap();
        assert_eq!(l.host, "2001:db8::1");
        assert_eq!(l.port, 8443);
    }
}
