//! macOS network configuration through the base system's tools (004 research
//! R2/R3): `ifconfig` for the tunnel address, `route` for routes, and `scutil`
//! for DNS, published as a dynamic-store service that overrides the primary
//! one. The user's persistent network settings are never written.
//!
//! Every command goes through [`CommandRunner`] and interface names through
//! [`IfNames`], so the exact commands are unit-tested on any OS.

use crate::unix_cmd::{CommandRunner, Output};
use std::io;
use std::net::Ipv4Addr;
use tracing::debug;
use vpn_core::traits::{NetChange, NetConfig};

/// MTU of the tunnel interface, as on Windows and Linux.
const TUNNEL_MTU: &str = "1400";

/// Dynamic-store service the tunnel is published as (004 data-model.md).
pub const DNS_SERVICE: &str = "State:/Network/Service/net.ipsec-client";

/// Maps interface indexes (`NetChange::if_id`) to names and back.
pub trait IfNames: Send + Sync {
    fn name(&self, index: u64) -> Option<String>;
    fn index(&self, name: &str) -> Option<u64>;
}

/// [`NetConfig`] for macOS. Interface ids are kernel interface indexes.
pub struct MacNetConfig<R: CommandRunner, N: IfNames> {
    run: R,
    names: N,
}

impl<R: CommandRunner, N: IfNames> MacNetConfig<R, N> {
    pub fn new(run: R, names: N) -> Self {
        Self { run, names }
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
            Err(tool_error(argv, &out))
        }
    }

    /// Like [`exec`](Self::exec) for undo steps: "already gone" counts as done.
    fn exec_revert(&self, argv: &[&str]) -> io::Result<()> {
        match self.exec(argv) {
            Err(e) if already_gone(&e.to_string()) => Ok(()),
            r => r.map(drop),
        }
    }

    fn scutil(&self, script: &str) -> io::Result<()> {
        debug!(target: "netconfig", script = %script.replace('\n', "; "), "scutil");
        let out = self.run.run_with_input(&["scutil"], script.as_bytes())?;
        if out.status_ok {
            Ok(())
        } else {
            Err(tool_error(&["scutil"], &out))
        }
    }

    fn require_if(&self, index: u64) -> io::Result<String> {
        self.names.name(index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("network interface {index} does not exist"),
            )
        })
    }

    /// The first IPv4 address on `dev`, from `ifconfig <dev>`.
    fn if_addr(&self, dev: &str) -> io::Result<Ipv4Addr> {
        let out = self.exec(&["ifconfig", dev])?;
        parse_ifconfig_inet(&out.stdout).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{dev} has no IPv4 address"),
            )
        })
    }
}

/// `route -n <verb> …` for one `NetChange::Route`.
fn route_argv(
    verb: &str,
    dest: Ipv4Addr,
    prefix: u8,
    next_hop: Ipv4Addr,
    dev: &str,
) -> Vec<String> {
    let mut v: Vec<String> = vec!["route".into(), "-n".into(), verb.into()];
    if prefix == 32 {
        v.extend(["-host".into(), dest.to_string()]);
    } else {
        v.extend(["-net".into(), format!("{dest}/{prefix}")]);
    }
    if next_hop.is_unspecified() {
        // On-link (the tunnel, or a gateway on the local network).
        v.extend(["-interface".into(), dev.into()]);
    } else {
        v.push(next_hop.to_string());
    }
    v
}

fn netmask(prefix: u8) -> Ipv4Addr {
    let bits = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    };
    Ipv4Addr::from(bits)
}

/// The `scutil` script that publishes the tunnel's DNS (004 research R3).
pub fn dns_apply_script(dev: &str, addr: Ipv4Addr, servers: &[Ipv4Addr]) -> String {
    let servers: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
    format!(
        "d.init\n\
         d.add Addresses * {addr}\n\
         d.add InterfaceName {dev}\n\
         d.add Router {addr}\n\
         d.add OverridePrimary # 1\n\
         set {DNS_SERVICE}/IPv4\n\
         d.init\n\
         d.add ServerAddresses * {}\n\
         set {DNS_SERVICE}/DNS\n\
         quit\n",
        servers.join(" ")
    )
}

/// The `scutil` script that removes what [`dns_apply_script`] published.
pub fn dns_revert_script() -> String {
    format!("remove {DNS_SERVICE}/IPv4\nremove {DNS_SERVICE}/DNS\nquit\n")
}

/// The first `inet` address in `ifconfig <dev>` output.
fn parse_ifconfig_inet(text: &str) -> Option<Ipv4Addr> {
    text.lines().find_map(|l| {
        let mut w = l.split_whitespace();
        (w.next()? == "inet").then(|| w.next()?.parse().ok())?
    })
}

/// `(interface, gateway)` from `route -n get <dest>`; the gateway is absent
/// for on-link destinations.
fn parse_route_get(text: &str) -> Option<(String, Option<Ipv4Addr>)> {
    let field = |key: &str| {
        text.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim() == key).then(|| v.trim().to_string())
        })
    };
    let dev = field("interface")?;
    // A link-layer "gateway" (e.g. `link#4`) means on-link.
    let gw = field("gateway").and_then(|g| g.parse().ok());
    Some((dev, gw))
}

fn tool_error(argv: &[&str], out: &Output) -> io::Error {
    // `route` reports some failures on stdout.
    let msg = format!("{} {}", out.stderr.trim(), out.stdout.trim());
    let msg = msg.trim();
    let kind = if msg.contains("Operation not permitted")
        || msg.contains("Permission denied")
        || msg.contains("must be root")
    {
        io::ErrorKind::PermissionDenied
    } else {
        io::ErrorKind::Other
    };
    io::Error::new(kind, format!("`{}` failed: {msg}", argv.join(" ")))
}

fn already_gone(msg: &str) -> bool {
    [
        "not in table",
        "does not exist",
        "No such process",
        "Can't assign requested address",
        "Device not configured",
    ]
    .iter()
    .any(|m| msg.contains(m))
}

impl<R: CommandRunner, N: IfNames> NetConfig for MacNetConfig<R, N> {
    fn apply(&self, change: &NetChange) -> io::Result<()> {
        match change {
            NetChange::AdapterAddress {
                if_id,
                addr,
                prefix,
            } => {
                let dev = self.require_if(*if_id)?;
                // utun is point-to-point: the address is also the destination.
                let a = addr.to_string();
                let mask = netmask(*prefix).to_string();
                self.exec(&[
                    "ifconfig", &dev, "inet", &a, &a, "netmask", &mask, "mtu", TUNNEL_MTU, "up",
                ])
                .map(drop)
            }
            NetChange::Route {
                if_id,
                dest,
                prefix,
                next_hop,
            } => {
                let dev = self.require_if(*if_id)?;
                let argv = route_argv("add", *dest, *prefix, *next_hop, &dev);
                self.exec(&argv.iter().map(String::as_str).collect::<Vec<_>>())
                    .map(drop)
            }
            NetChange::Dns { if_id, servers } => {
                if servers.is_empty() {
                    return Ok(());
                }
                let dev = self.require_if(*if_id)?;
                let addr = self.if_addr(&dev)?;
                self.scutil(&dns_apply_script(&dev, addr, servers))
            }
            NetChange::ResolvConf { .. } => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "resolv.conf changes are Linux-only",
            )),
        }
    }

    fn revert(&self, change: &NetChange) -> io::Result<()> {
        match change {
            NetChange::AdapterAddress { if_id, addr, .. } => {
                // Gone with the utun when the service exited.
                let Some(dev) = self.names.name(*if_id) else {
                    return Ok(());
                };
                let a = addr.to_string();
                self.exec_revert(&["ifconfig", &dev, "inet", &a, "delete"])
            }
            NetChange::Route {
                if_id,
                dest,
                prefix,
                next_hop,
            } => {
                // Routes through a vanished utun went with it.
                let Some(dev) = self.names.name(*if_id) else {
                    return Ok(());
                };
                let argv = route_argv("delete", *dest, *prefix, *next_hop, &dev);
                self.exec_revert(&argv.iter().map(String::as_str).collect::<Vec<_>>())
            }
            // The key names are fixed, so this works without the interface.
            NetChange::Dns { .. } => self.scutil(&dns_revert_script()),
            NetChange::ResolvConf { .. } => Ok(()),
        }
    }

    fn best_route(&self, dest: Ipv4Addr) -> io::Result<(u64, Ipv4Addr)> {
        let d = dest.to_string();
        let out = self.exec(&["route", "-n", "get", &d])?;
        let (dev, gw) = parse_route_get(&out.stdout).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected `route -n get {d}` output"),
            )
        })?;
        let index = self.names.index(&dev).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("interface {dev} vanished"))
        })?;
        // On-link destinations: next hop 0.0.0.0, as on Windows and Linux.
        Ok((index, gw.unwrap_or(Ipv4Addr::UNSPECIFIED)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unix_cmd::fake::{fail, ok, FakeRunner};

    /// utun4 = 14, en0 = 4.
    struct Names;
    impl IfNames for Names {
        fn name(&self, index: u64) -> Option<String> {
            match index {
                14 => Some("utun4".into()),
                4 => Some("en0".into()),
                _ => None,
            }
        }
        fn index(&self, name: &str) -> Option<u64> {
            match name {
                "utun4" => Some(14),
                "en0" => Some(4),
                _ => None,
            }
        }
    }

    fn cfg() -> MacNetConfig<FakeRunner, Names> {
        MacNetConfig::new(FakeRunner::new(), Names)
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    const ROUTE_GET_VIA: &str = "   route to: 203.0.113.9
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
";

    const ROUTE_GET_ONLINK: &str = "   route to: 192.168.1.20
destination: 192.168.1.0
       mask: 255.255.255.0
  interface: en0
      flags: <UP,DONE,CLONING>
";

    const IFCONFIG_UTUN: &str = "utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400
\tinet 10.99.2.5 --> 10.99.2.5 netmask 0xffffffff
";

    #[test]
    fn address_is_point_to_point_with_mtu() {
        let c = cfg();
        c.apply(&NetChange::AdapterAddress {
            if_id: 14,
            addr: ip("10.99.2.5"),
            prefix: 32,
        })
        .unwrap();
        c.revert(&NetChange::AdapterAddress {
            if_id: 14,
            addr: ip("10.99.2.5"),
            prefix: 32,
        })
        .unwrap();
        assert_eq!(
            c.runner().calls(),
            [
                "ifconfig utun4 inet 10.99.2.5 10.99.2.5 netmask 255.255.255.255 mtu 1400 up",
                "ifconfig utun4 inet 10.99.2.5 delete",
            ]
        );
    }

    #[test]
    fn tunnel_routes_go_via_the_interface() {
        let c = cfg();
        let r = NetChange::Route {
            if_id: 14,
            dest: ip("0.0.0.0"),
            prefix: 1,
            next_hop: Ipv4Addr::UNSPECIFIED,
        };
        c.apply(&r).unwrap();
        c.revert(&r).unwrap();
        assert_eq!(
            c.runner().calls(),
            [
                "route -n add -net 0.0.0.0/1 -interface utun4",
                "route -n delete -net 0.0.0.0/1 -interface utun4",
            ]
        );
    }

    #[test]
    fn gateway_host_route_uses_the_physical_next_hop() {
        let c = cfg();
        let r = NetChange::Route {
            if_id: 4,
            dest: ip("203.0.113.9"),
            prefix: 32,
            next_hop: ip("192.168.1.1"),
        };
        c.apply(&r).unwrap();
        c.revert(&r).unwrap();
        // On-link gateway (same LAN): no next hop, via the interface.
        c.apply(&NetChange::Route {
            if_id: 4,
            dest: ip("192.168.1.20"),
            prefix: 32,
            next_hop: Ipv4Addr::UNSPECIFIED,
        })
        .unwrap();
        assert_eq!(
            c.runner().calls(),
            [
                "route -n add -host 203.0.113.9 192.168.1.1",
                "route -n delete -host 203.0.113.9 192.168.1.1",
                "route -n add -host 192.168.1.20 -interface en0",
            ]
        );
    }

    #[test]
    fn reverts_treat_already_gone_as_success() {
        for msg in [
            "route: writing to routing socket: not in table",
            "ifconfig: interface utun4 does not exist",
            "ifconfig: ioctl (SIOCDIFADDR): Can't assign requested address",
        ] {
            let c = cfg();
            c.runner().on("", fail(msg));
            c.revert(&NetChange::Route {
                if_id: 14,
                dest: ip("10.0.0.0"),
                prefix: 8,
                next_hop: Ipv4Addr::UNSPECIFIED,
            })
            .unwrap();
            c.revert(&NetChange::AdapterAddress {
                if_id: 14,
                addr: ip("10.99.2.5"),
                prefix: 32,
            })
            .unwrap();
        }
        // A real failure is reported, with stdout included (`route` writes there).
        let c = cfg();
        c.runner().on(
            "route",
            Output {
                status_ok: false,
                stdout: "add net 10.0.0.0: gateway utun4: File exists".into(),
                stderr: String::new(),
            },
        );
        let e = c
            .apply(&NetChange::Route {
                if_id: 14,
                dest: ip("10.0.0.0"),
                prefix: 8,
                next_hop: Ipv4Addr::UNSPECIFIED,
            })
            .unwrap_err();
        assert!(e.to_string().contains("File exists"), "{e}");
    }

    #[test]
    fn vanished_utun_makes_reverts_no_ops_and_applies_fail() {
        let c = cfg();
        let gone = NetChange::Route {
            if_id: 99,
            dest: ip("10.0.0.0"),
            prefix: 8,
            next_hop: Ipv4Addr::UNSPECIFIED,
        };
        c.revert(&gone).unwrap();
        c.revert(&NetChange::AdapterAddress {
            if_id: 99,
            addr: ip("10.99.2.5"),
            prefix: 32,
        })
        .unwrap();
        assert!(c.runner().calls().is_empty());
        assert_eq!(c.apply(&gone).unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn permission_errors_are_classified() {
        let c = cfg();
        c.runner()
            .on("route", fail("route: must be root to alter routing table"));
        let e = c
            .apply(&NetChange::Route {
                if_id: 14,
                dest: ip("10.0.0.0"),
                prefix: 8,
                next_hop: Ipv4Addr::UNSPECIFIED,
            })
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn best_route_parses_gateway_and_on_link() {
        let c = cfg();
        c.runner()
            .once("route -n get 203.0.113.9", ok(ROUTE_GET_VIA));
        assert_eq!(
            c.best_route(ip("203.0.113.9")).unwrap(),
            (4, ip("192.168.1.1"))
        );
        c.runner()
            .once("route -n get 192.168.1.20", ok(ROUTE_GET_ONLINK));
        assert_eq!(
            c.best_route(ip("192.168.1.20")).unwrap(),
            (4, Ipv4Addr::UNSPECIFIED)
        );
        c.runner().once("route -n get", ok("garbage"));
        assert_eq!(
            c.best_route(ip("1.1.1.1")).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn link_layer_gateway_counts_as_on_link() {
        let text = ROUTE_GET_ONLINK.replace("  interface", "    gateway: link#4\n  interface");
        assert_eq!(parse_route_get(&text), Some(("en0".into(), None)));
    }

    #[test]
    fn dns_publishes_an_overriding_service_and_removes_it() {
        let c = cfg();
        c.runner().on("ifconfig utun4", ok(IFCONFIG_UTUN));
        let dns = NetChange::Dns {
            if_id: 14,
            servers: vec![ip("10.99.1.53"), ip("10.99.1.54")],
        };
        c.apply(&dns).unwrap();
        c.revert(&dns).unwrap();
        let inputs = c.runner().inputs();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0].0, "scutil");
        assert_eq!(
            inputs[0].1,
            "d.init
d.add Addresses * 10.99.2.5
d.add InterfaceName utun4
d.add Router 10.99.2.5
d.add OverridePrimary # 1
set State:/Network/Service/net.ipsec-client/IPv4
d.init
d.add ServerAddresses * 10.99.1.53 10.99.1.54
set State:/Network/Service/net.ipsec-client/DNS
quit
"
        );
        assert_eq!(
            inputs[1].1,
            "remove State:/Network/Service/net.ipsec-client/IPv4
remove State:/Network/Service/net.ipsec-client/DNS
quit
"
        );
    }

    #[test]
    fn dns_revert_works_without_the_interface_and_empty_dns_applies_nothing() {
        let c = cfg();
        c.revert(&NetChange::Dns {
            if_id: 99,
            servers: vec![ip("10.99.1.53")],
        })
        .unwrap();
        c.apply(&NetChange::Dns {
            if_id: 14,
            servers: vec![],
        })
        .unwrap();
        assert_eq!(c.runner().inputs().len(), 1);
        assert!(c.runner().calls().iter().all(|l| l == "scutil"));
    }

    #[test]
    fn resolv_conf_is_not_a_macos_change() {
        let c = cfg();
        let rc = NetChange::ResolvConf {
            backup: String::new(),
        };
        assert_eq!(c.apply(&rc).unwrap_err().kind(), io::ErrorKind::Unsupported);
        c.revert(&rc).unwrap();
    }

    #[test]
    fn netmask_from_prefix() {
        assert_eq!(netmask(32), ip("255.255.255.255"));
        assert_eq!(netmask(24), ip("255.255.255.0"));
        assert_eq!(netmask(1), ip("128.0.0.0"));
        assert_eq!(netmask(0), ip("0.0.0.0"));
    }

    #[test]
    fn ifconfig_inet_parsing() {
        assert_eq!(parse_ifconfig_inet(IFCONFIG_UTUN), Some(ip("10.99.2.5")));
        assert_eq!(parse_ifconfig_inet("utun4: flags=0<> mtu 1400\n"), None);
    }
}
