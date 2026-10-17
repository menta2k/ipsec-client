//! Platform abstractions (Constitution IV/V). The engine only talks to the OS
//! through these traits; Windows implementations live in `ipsec-service`, and
//! test doubles in [`crate::mock`].

use serde::{Deserialize, Serialize};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

/// A connected UDP socket.
pub trait UdpLink: Send + Sync {
    fn send(&self, buf: &[u8]) -> io::Result<usize>;
    /// Receive one datagram, waiting at most `timeout`. A timeout is reported as
    /// `ErrorKind::WouldBlock` or `ErrorKind::TimedOut`.
    fn recv(&self, buf: &mut [u8], timeout: Duration) -> io::Result<usize>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn peer_addr(&self) -> io::Result<SocketAddr>;
}

/// Creates UDP links and resolves gateway names.
pub trait UdpFactory: Send + Sync {
    /// Bind a local IPv4 socket on `local_port` (0 = ephemeral) and connect it
    /// to `peer`.
    fn connect(&self, local_port: u16, peer: SocketAddrV4) -> io::Result<Arc<dyn UdpLink>>;

    /// Resolve a gateway host (DNS name or IPv4 literal) to an IPv4 address.
    fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddrV4> {
        (host, port)
            .to_socket_addrs()?
            .find_map(|a| match a {
                SocketAddr::V4(v4) => Some(v4),
                SocketAddr::V6(_) => None,
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no IPv4 address for gateway"))
    }
}

/// A virtual layer-3 adapter (Wintun on Windows).
pub trait TunDevice: Send + Sync {
    /// Block until the OS hands us an outbound IP packet. `Ok(None)` means the
    /// device was shut down.
    fn recv(&self) -> io::Result<Option<Vec<u8>>>;
    /// Deliver an inbound IP packet to the OS.
    fn send(&self, packet: &[u8]) -> io::Result<()>;
    /// Unblock `recv` and stop the device.
    fn shutdown(&self);
    /// OS interface identifier (the interface LUID on Windows).
    fn if_id(&self) -> u64;
}

pub trait TunFactory: Send + Sync {
    /// Create (or reuse) the client's adapter.
    fn create(&self) -> io::Result<Arc<dyn TunDevice>>;
    /// Remove any adapter left behind by a previous unclean exit (FR-008).
    fn remove_stale(&self) -> io::Result<()>;
}

/// One reversible network configuration change, journaled before it is
/// applied so it can be undone even after a crash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum NetChange {
    AdapterAddress {
        if_id: u64,
        addr: Ipv4Addr,
        prefix: u8,
    },
    Route {
        if_id: u64,
        dest: Ipv4Addr,
        prefix: u8,
        next_hop: Ipv4Addr,
    },
    Dns {
        if_id: u64,
        servers: Vec<Ipv4Addr>,
    },
    /// Linux without systemd-resolved: the original `/etc/resolv.conf`,
    /// journaled before the file is rewritten; reverting writes it back.
    ResolvConf {
        backup: String,
    },
}

pub trait NetConfig: Send + Sync {
    fn apply(&self, change: &NetChange) -> io::Result<()>;
    fn revert(&self, change: &NetChange) -> io::Result<()>;
    /// The interface and next hop the OS currently uses to reach `dest`
    /// (used for the gateway host route in full-tunnel mode).
    fn best_route(&self, dest: Ipv4Addr) -> io::Result<(u64, Ipv4Addr)>;
}

/// Persists the list of applied [`NetChange`]s.
pub trait JournalStore: Send + Sync {
    fn load(&self) -> io::Result<Vec<NetChange>>;
    fn save(&self, changes: &[NetChange]) -> io::Result<()>;
}

/// Encrypts secrets at rest (DPAPI on Windows).
pub trait SecretProtector: Send + Sync {
    fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>>;
    fn unprotect(&self, blob: &[u8]) -> io::Result<Zeroizing<Vec<u8>>>;
}

// ---------------------------------------------------------------------------
// Portable implementations
// ---------------------------------------------------------------------------

/// `UdpLink` over `std::net::UdpSocket`. The read timeout is cached so the
/// per-packet receive path does not issue a syscall to re-set it.
pub struct StdUdpLink {
    sock: UdpSocket,
    timeout: Mutex<Option<Duration>>,
}

impl UdpLink for StdUdpLink {
    fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.sock.send(buf)
    }
    fn recv(&self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        let timeout = timeout.max(Duration::from_millis(1));
        {
            let mut cur = self.timeout.lock().unwrap();
            if *cur != Some(timeout) {
                self.sock.set_read_timeout(Some(timeout))?;
                *cur = Some(timeout);
            }
        }
        self.sock.recv(buf)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.sock.peer_addr()
    }
}

/// `UdpFactory` over the standard library.
pub struct StdUdpFactory;

impl UdpFactory for StdUdpFactory {
    fn connect(&self, local_port: u16, peer: SocketAddrV4) -> io::Result<Arc<dyn UdpLink>> {
        let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, local_port))?;
        sock.connect(peer)?;
        Ok(Arc::new(StdUdpLink {
            sock,
            timeout: Mutex::new(None),
        }))
    }
}

/// JSON-file journal (written atomically via a temp file + rename).
pub struct FileJournal {
    pub path: std::path::PathBuf,
}

impl JournalStore for FileJournal {
    fn load(&self) -> io::Result<Vec<NetChange>> {
        match std::fs::read(&self.path) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }
    fn save(&self, changes: &[NetChange]) -> io::Result<()> {
        let body = serde_json::to_vec_pretty(changes)?;
        crate::store::atomic_write(&self.path, &body)
    }
}

/// Is `e` a receive timeout?
pub fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf_change_round_trips() {
        let c = NetChange::ResolvConf {
            backup: "nameserver 192.0.2.53\nsearch lan\n".into(),
        };
        let s = serde_json::to_string(&c).unwrap();
        assert!(s.contains(r#""kind":"ResolvConf""#), "{s}");
        assert_eq!(serde_json::from_str::<NetChange>(&s).unwrap(), c);
    }

    #[test]
    fn journal_written_by_001_still_parses() {
        let old = r#"[
            {"kind":"AdapterAddress","if_id":7,"addr":"10.0.0.2","prefix":32},
            {"kind":"Route","if_id":7,"dest":"0.0.0.0","prefix":1,"next_hop":"0.0.0.0"},
            {"kind":"Dns","if_id":7,"servers":["10.0.0.53"]}
        ]"#;
        let v: Vec<NetChange> = serde_json::from_str(old).unwrap();
        assert_eq!(v.len(), 3);
    }
}
