//! Linux network configuration through the distribution's tools (002 research
//! R2/R3): `ip` (iproute2) for addresses and routes, `resolvectl` for DNS.
//!
//! Every command goes through [`CommandRunner`], so the exact argv the service
//! issues is unit-tested with `FakeRunner` on any OS.

use serde_json::Value;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use tracing::debug;
use vpn_core::traits::{NetChange, NetConfig};

/// MTU of the tunnel interface, as on Windows (001 research R13).
const TUNNEL_MTU: &str = "1400";

pub use crate::unix_cmd::{CommandRunner, Output, SystemRunner};

/// How DNS is applied (research R3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsMode {
    /// systemd-resolved per-link configuration via `resolvectl`.
    Resolved,
    /// No resolved: back up and rewrite this resolver file.
    ResolvConf(PathBuf),
}

/// [`NetConfig`] for Linux. Interface ids are kernel interface indexes.
pub struct LinuxNetConfig<R: CommandRunner = SystemRunner> {
    run: R,
    dns: DnsMode,
}

impl<R: CommandRunner> LinuxNetConfig<R> {
    pub fn with_dns(run: R, dns: DnsMode) -> Self {
        Self { run, dns }
    }

    /// Use resolved when `resolvectl status` works, else rewrite `resolv_conf`.
    pub fn detect(run: R, resolv_conf: PathBuf) -> Self {
        let resolved = run
            .run(&["resolvectl", "status"])
            .map(|o| o.status_ok)
            .unwrap_or(false);
        let dns = if resolved {
            DnsMode::Resolved
        } else {
            DnsMode::ResolvConf(resolv_conf)
        };
        Self::with_dns(run, dns)
    }

    pub fn dns_mode(&self) -> &DnsMode {
        &self.dns
    }

    #[cfg(test)]
    pub fn runner(&self) -> &R {
        &self.run
    }

    /// Run a command; a failure becomes an error carrying the tool's message.
    fn exec(&self, argv: &[&str]) -> io::Result<Output> {
        debug!(target: "netconfig", cmd = %argv.join(" "), "run");
        let out = self.run.run(argv)?;
        if out.status_ok {
            Ok(out)
        } else {
            Err(tool_error(argv, &out.stderr))
        }
    }

    /// Like [`exec`](Self::exec) for undo steps: "already gone" counts as done.
    fn exec_revert(&self, argv: &[&str]) -> io::Result<()> {
        match self.exec(argv) {
            Err(e) if already_gone(&e.to_string()) => Ok(()),
            r => r.map(drop),
        }
    }

    /// `(index, name)` of every interface.
    fn links(&self) -> io::Result<Vec<(u64, String)>> {
        let out = self.exec(&["ip", "-j", "link", "show"])?;
        let v: Value = serde_json::from_str(&out.stdout).map_err(bad_json)?;
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|l| {
                        Some((l["ifindex"].as_u64()?, l["ifname"].as_str()?.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn if_name(&self, index: u64) -> io::Result<Option<String>> {
        Ok(self
            .links()?
            .into_iter()
            .find(|(i, _)| *i == index)
            .map(|(_, n)| n))
    }

    fn require_if(&self, index: u64) -> io::Result<String> {
        self.if_name(index)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("network interface {index} does not exist"),
            )
        })
    }
}

fn route_argv<'a>(verb: &'a str, net: &'a str, via: Option<&'a str>, dev: &'a str) -> Vec<&'a str> {
    let mut v = vec!["ip", "route", verb, net];
    if let Some(nh) = via {
        v.extend(["via", nh]);
    }
    v.extend(["dev", dev]);
    v
}

/// `0.0.0.0` means an on-link route (no `via`), as on Windows.
fn via(next_hop: &str) -> Option<&str> {
    (next_hop != "0.0.0.0").then_some(next_hop)
}

fn write_resolv_conf(path: &Path, contents: &str) -> io::Result<()> {
    // In place, not via rename: /etc may be read-only to us while the file
    // itself is writable, and the path may be a symlink.
    std::fs::write(path, contents).map_err(|e| needs_resolved(path, e))
}

fn tool_error(argv: &[&str], stderr: &str) -> io::Error {
    let msg = stderr.trim();
    let kind = if msg.contains("Operation not permitted") || msg.contains("Permission denied") {
        io::ErrorKind::PermissionDenied
    } else {
        io::ErrorKind::Other
    };
    io::Error::new(kind, format!("`{}` failed: {msg}", argv.join(" ")))
}

fn already_gone(msg: &str) -> bool {
    [
        "Cannot find device",
        "No such device",
        "No such process",
        "No such file",
        "Cannot assign requested address",
    ]
    .iter()
    .any(|m| msg.contains(m))
}

fn bad_json(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected `ip -j` output: {e}"),
    )
}

fn needs_resolved(path: &Path, e: io::Error) -> io::Error {
    io::Error::new(
        e.kind(),
        format!(
            "cannot update {} ({e}); install and enable systemd-resolved so DNS can be set per interface",
            path.display()
        ),
    )
}

impl<R: CommandRunner> NetConfig for LinuxNetConfig<R> {
    fn prepare(&self, change: &NetChange) -> io::Result<Option<NetChange>> {
        match (change, &self.dns) {
            (NetChange::Dns { .. }, DnsMode::ResolvConf(path)) => {
                let backup = std::fs::read_to_string(path).map_err(|e| needs_resolved(path, e))?;
                Ok(Some(NetChange::ResolvConf { backup }))
            }
            _ => Ok(None),
        }
    }

    fn apply(&self, change: &NetChange) -> io::Result<()> {
        match change {
            NetChange::AdapterAddress {
                if_id,
                addr,
                prefix,
            } => {
                let dev = self.require_if(*if_id)?;
                self.exec(&["ip", "link", "set", "dev", &dev, "mtu", TUNNEL_MTU, "up"])?;
                let net = format!("{addr}/{prefix}");
                self.exec(&["ip", "addr", "add", &net, "dev", &dev])
                    .map(drop)
            }
            NetChange::Route {
                if_id,
                dest,
                prefix,
                next_hop,
            } => {
                let dev = self.require_if(*if_id)?;
                let net = format!("{dest}/{prefix}");
                let nh = next_hop.to_string();
                self.exec(&route_argv("replace", &net, via(&nh), &dev))
                    .map(drop)
            }
            NetChange::Dns { if_id, servers } => match &self.dns {
                DnsMode::Resolved => {
                    let dev = self.require_if(*if_id)?;
                    let servers: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
                    let mut argv = vec!["resolvectl", "dns", dev.as_str()];
                    argv.extend(servers.iter().map(String::as_str));
                    self.exec(&argv)?;
                    // "~." makes this link preferred for every lookup, like the
                    // metric-1 VPN adapter on Windows.
                    self.exec(&["resolvectl", "domain", &dev, "~."]).map(drop)
                }
                DnsMode::ResolvConf(path) => {
                    let mut text = String::from(
                        "# Written by ipsec-client while the VPN is connected; restored on disconnect.\n",
                    );
                    for s in servers {
                        text.push_str(&format!("nameserver {s}\n"));
                    }
                    write_resolv_conf(path, &text)
                }
            },
            // prepare() captured the backup; journaling it was the point.
            NetChange::ResolvConf { .. } => Ok(()),
        }
    }

    fn revert(&self, change: &NetChange) -> io::Result<()> {
        match change {
            NetChange::AdapterAddress {
                if_id,
                addr,
                prefix,
            } => {
                let Some(dev) = self.if_name(*if_id)? else {
                    return Ok(());
                };
                let net = format!("{addr}/{prefix}");
                self.exec_revert(&["ip", "addr", "del", &net, "dev", &dev])
            }
            NetChange::Route {
                if_id,
                dest,
                prefix,
                next_hop,
            } => {
                let Some(dev) = self.if_name(*if_id)? else {
                    return Ok(());
                };
                let net = format!("{dest}/{prefix}");
                let nh = next_hop.to_string();
                self.exec_revert(&route_argv("del", &net, via(&nh), &dev))
            }
            NetChange::Dns { if_id, .. } => match &self.dns {
                DnsMode::Resolved => {
                    let Some(dev) = self.if_name(*if_id)? else {
                        return Ok(());
                    };
                    self.exec_revert(&["resolvectl", "revert", &dev])
                }
                // Restored by reverting the ResolvConf entry journaled before it.
                DnsMode::ResolvConf(_) => Ok(()),
            },
            NetChange::ResolvConf { backup } => {
                let path = match &self.dns {
                    DnsMode::ResolvConf(p) => p.clone(),
                    // resolved appeared since the backup was taken; the file is
                    // still the one we changed.
                    DnsMode::Resolved => PathBuf::from("/etc/resolv.conf"),
                };
                write_resolv_conf(&path, backup)
            }
        }
    }

    fn best_route(&self, dest: Ipv4Addr) -> io::Result<(u64, Ipv4Addr)> {
        let d = dest.to_string();
        let out = self.exec(&["ip", "-j", "route", "get", &d])?;
        let v: Value = serde_json::from_str(&out.stdout).map_err(bad_json)?;
        let r = &v[0];
        let dev = r["dev"].as_str().ok_or_else(|| bad_json("no `dev`"))?;
        // On-link destinations have no gateway: next hop 0.0.0.0, as on Windows.
        let next_hop = match r["gateway"].as_str() {
            Some(g) => g
                .parse()
                .map_err(|_| bad_json(format!("bad gateway {g}")))?,
            None => Ipv4Addr::UNSPECIFIED,
        };
        let index = self
            .links()?
            .into_iter()
            .find(|(_, n)| n == dev)
            .map(|(i, _)| i)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("interface {dev} vanished"))
            })?;
        Ok((index, next_hop))
    }
}

#[cfg(test)]
pub use crate::unix_cmd::fake;

#[cfg(test)]
mod tests {
    use super::fake::{fail, ok, FakeRunner};
    use super::*;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use vpn_core::traits::{NetChange, NetConfig};

    const LINKS: &str = r#"[{"ifindex":1,"ifname":"lo"},{"ifindex":2,"ifname":"eth0"},{"ifindex":7,"ifname":"ipsec0"}]"#;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn cfg(dns: DnsMode) -> LinuxNetConfig<FakeRunner> {
        let r = FakeRunner::new();
        r.on("ip -j link show", ok(LINKS));
        LinuxNetConfig::with_dns(r, dns)
    }

    /// Commands issued, without the read-only interface lookups.
    fn writes(c: &LinuxNetConfig<FakeRunner>) -> Vec<String> {
        c.runner()
            .calls()
            .into_iter()
            .filter(|l| l != "ip -j link show")
            .collect()
    }

    fn temp_file(tag: &str, contents: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ipsec-resolv-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&p, contents).unwrap();
        p
    }

    fn tunnel_route(dest: &str, prefix: u8) -> NetChange {
        NetChange::Route {
            if_id: 7,
            dest: ip(dest),
            prefix,
            next_hop: Ipv4Addr::UNSPECIFIED,
        }
    }

    #[test]
    fn adapter_address_brings_link_up_with_mtu_then_adds_address() {
        let c = cfg(DnsMode::Resolved);
        let ch = NetChange::AdapterAddress {
            if_id: 7,
            addr: ip("10.99.2.5"),
            prefix: 32,
        };
        c.apply(&ch).unwrap();
        c.revert(&ch).unwrap();
        assert_eq!(
            writes(&c),
            [
                "ip link set dev ipsec0 mtu 1400 up",
                "ip addr add 10.99.2.5/32 dev ipsec0",
                "ip addr del 10.99.2.5/32 dev ipsec0",
            ]
        );
    }

    #[test]
    fn on_link_and_gateway_routes() {
        let c = cfg(DnsMode::Resolved);
        let tunnel = tunnel_route("0.0.0.0", 1);
        let gw = NetChange::Route {
            if_id: 2,
            dest: ip("203.0.113.9"),
            prefix: 32,
            next_hop: ip("192.168.1.1"),
        };
        c.apply(&tunnel).unwrap();
        c.apply(&gw).unwrap();
        c.revert(&gw).unwrap();
        c.revert(&tunnel).unwrap();
        assert_eq!(
            writes(&c),
            [
                "ip route replace 0.0.0.0/1 dev ipsec0",
                "ip route replace 203.0.113.9/32 via 192.168.1.1 dev eth0",
                "ip route del 203.0.113.9/32 via 192.168.1.1 dev eth0",
                "ip route del 0.0.0.0/1 dev ipsec0",
            ]
        );
    }

    #[test]
    fn best_route_via_gateway_and_on_link() {
        let c = cfg(DnsMode::Resolved);
        c.runner().once(
            "ip -j route get 203.0.113.9",
            ok(r#"[{"dst":"203.0.113.9","gateway":"192.168.1.1","dev":"eth0","prefsrc":"192.168.1.20","flags":[],"uid":1000,"cache":[]}]"#),
        );
        assert_eq!(
            c.best_route(ip("203.0.113.9")).unwrap(),
            (2, ip("192.168.1.1"))
        );
        // Directly connected: no gateway, next hop 0.0.0.0 (as on Windows).
        c.runner().once(
            "ip -j route get 192.168.1.50",
            ok(r#"[{"dst":"192.168.1.50","dev":"eth0","prefsrc":"192.168.1.20","flags":[],"cache":[]}]"#),
        );
        assert_eq!(
            c.best_route(ip("192.168.1.50")).unwrap(),
            (2, Ipv4Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn best_route_errors_are_reported() {
        let c = cfg(DnsMode::Resolved);
        c.runner().once(
            "ip -j route get",
            fail("RTNETLINK answers: Network is unreachable"),
        );
        let e = c.best_route(ip("198.51.100.1")).unwrap_err();
        assert!(e.to_string().contains("Network is unreachable"), "{e}");
        c.runner().once("ip -j route get", ok("not json"));
        assert!(c.best_route(ip("198.51.100.1")).is_err());
    }

    #[test]
    fn revert_treats_already_gone_as_success() {
        for msg in [
            "Cannot find device \"ipsec0\"",
            "RTNETLINK answers: No such device",
            "RTNETLINK answers: No such process",
            "RTNETLINK answers: Cannot assign requested address",
        ] {
            let c = cfg(DnsMode::Resolved);
            c.runner().once("ip route del", fail(msg));
            c.revert(&tunnel_route("10.0.0.0", 8))
                .unwrap_or_else(|e| panic!("{msg}: {e}"));
        }
        // A device that no longer exists at all (crash cleanup) is skipped.
        let c = cfg(DnsMode::Resolved);
        let gone = NetChange::AdapterAddress {
            if_id: 42,
            addr: ip("10.0.0.2"),
            prefix: 32,
        };
        c.revert(&gone).unwrap();
        assert!(writes(&c).is_empty());
        // Real failures still surface.
        let c = cfg(DnsMode::Resolved);
        c.runner().once(
            "ip route del",
            fail("RTNETLINK answers: Operation not permitted"),
        );
        assert!(c.revert(&tunnel_route("10.0.0.0", 8)).is_err());
    }

    #[test]
    fn apply_errors_carry_the_tool_message() {
        let c = cfg(DnsMode::Resolved);
        c.runner().once(
            "ip route replace",
            fail("RTNETLINK answers: Operation not permitted"),
        );
        let e = c.apply(&tunnel_route("10.0.0.0", 8)).unwrap_err();
        assert!(e.to_string().contains("Operation not permitted"), "{e}");
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        // Applying to an interface that does not exist is an error, not a no-op.
        let c = cfg(DnsMode::Resolved);
        assert!(c
            .apply(&NetChange::Route {
                if_id: 42,
                dest: ip("10.0.0.0"),
                prefix: 8,
                next_hop: Ipv4Addr::UNSPECIFIED,
            })
            .is_err());
    }

    #[test]
    fn resolved_dns_sets_servers_and_catch_all_domain() {
        let c = cfg(DnsMode::Resolved);
        let ch = NetChange::Dns {
            if_id: 7,
            servers: vec![ip("10.99.1.53"), ip("10.99.1.54")],
        };
        assert_eq!(c.prepare(&ch).unwrap(), None);
        c.apply(&ch).unwrap();
        c.revert(&ch).unwrap();
        assert_eq!(
            writes(&c),
            [
                "resolvectl dns ipsec0 10.99.1.53 10.99.1.54",
                "resolvectl domain ipsec0 ~.",
                "resolvectl revert ipsec0",
            ]
        );
        // The link vanished (crash): resolved already dropped its settings.
        let c = cfg(DnsMode::Resolved);
        c.revert(&NetChange::Dns {
            if_id: 99,
            servers: vec![ip("10.99.1.53")],
        })
        .unwrap();
        assert!(writes(&c).is_empty());
    }

    #[test]
    fn resolv_conf_fallback_backs_up_rewrites_and_restores() {
        let original = "# managed by hand\nnameserver 192.168.1.1\nsearch lan\n";
        let path = temp_file("fallback", original);
        let c = cfg(DnsMode::ResolvConf(path.clone()));
        let dns = NetChange::Dns {
            if_id: 7,
            servers: vec![ip("10.99.1.53")],
        };
        // The engine journals the backup returned by prepare() first.
        let backup = c.prepare(&dns).unwrap().expect("backup change");
        assert_eq!(
            backup,
            NetChange::ResolvConf {
                backup: original.into()
            }
        );
        c.apply(&backup).unwrap();
        c.apply(&dns).unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("nameserver 10.99.1.53"), "{written}");
        assert!(!written.contains("192.168.1.1"), "{written}");
        // Revert in reverse order restores the original byte for byte.
        c.revert(&dns).unwrap();
        c.revert(&backup).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert!(writes(&c).is_empty(), "no resolvectl in fallback mode");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn resolv_conf_unreadable_suggests_resolved() {
        let dir = std::env::temp_dir().join(format!("ipsec-resolv-missing-{}", std::process::id()));
        let c = cfg(DnsMode::ResolvConf(dir.join("nope").join("resolv.conf")));
        let dns = NetChange::Dns {
            if_id: 7,
            servers: vec![ip("10.99.1.53")],
        };
        let e = c.prepare(&dns).unwrap_err();
        assert!(e.to_string().contains("systemd-resolved"), "{e}");
    }

    #[test]
    fn detects_resolved_from_resolvectl_status() {
        let r = FakeRunner::new();
        r.on("resolvectl status", ok("Global\n"));
        assert!(matches!(
            LinuxNetConfig::detect(r, PathBuf::from("/etc/resolv.conf")).dns_mode(),
            DnsMode::Resolved
        ));
        let r = FakeRunner::new();
        r.on(
            "resolvectl status",
            fail(
                "Failed to get global data: Unit dbus-org.freedesktop.resolve1.service not found.",
            ),
        );
        assert!(matches!(
            LinuxNetConfig::detect(r, PathBuf::from("/etc/resolv.conf")).dns_mode(),
            DnsMode::ResolvConf(_)
        ));
    }
}
