//! TUN device over `/dev/net/tun` (002 research R1).
//!
//! The device is not persistent: the kernel deletes the interface, with its
//! addresses and routes, as soon as the descriptor closes, including when the
//! service dies. That gives crash cleanup of the adapter for free.

use super::sys;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, info};
use vpn_core::traits::{TunDevice, TunFactory};

/// Interface names tried in order; an existing interface is never taken over.
const NAMES: [&str; 10] = [
    "ipsec0", "ipsec1", "ipsec2", "ipsec3", "ipsec4", "ipsec5", "ipsec6", "ipsec7", "ipsec8",
    "ipsec9",
];
/// How long `recv` blocks before re-checking for `shutdown`.
const POLL_MS: i32 = 250;
const MAX_PACKET: usize = 65_535;

pub struct LinuxTunFactory;

impl TunFactory for LinuxTunFactory {
    fn create(&self) -> io::Result<Arc<dyn TunDevice>> {
        for name in NAMES {
            if sys::if_index(name)?.is_some() {
                debug!(target: "tun", name, "interface name in use, trying the next");
                continue;
            }
            // std opens with O_CLOEXEC, so `ip` children never inherit it.
            let file = File::options()
                .read(true)
                .write(true)
                .open("/dev/net/tun")?;
            match sys::tun_set_iff(file.as_raw_fd(), name) {
                Ok(actual) => {
                    let index = sys::if_index(&actual)?.ok_or_else(|| {
                        io::Error::other(format!("{actual} vanished right after creation"))
                    })?;
                    info!(target: "tun", name = %actual, index, "tunnel interface created");
                    return Ok(Arc::new(LinuxTunDevice {
                        file,
                        name: actual,
                        index,
                        stop: AtomicBool::new(false),
                    }));
                }
                Err(e) if e.raw_os_error() == Some(libc::EBUSY) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "no free interface name (ipsec0-ipsec9 are all in use)",
        ))
    }

    fn remove_stale(&self) -> io::Result<()> {
        // Our devices are not persistent: the kernel already removed any
        // interface a crashed run left behind.
        Ok(())
    }
}

pub struct LinuxTunDevice {
    file: File,
    name: String,
    index: u64,
    stop: AtomicBool,
}

impl TunDevice for LinuxTunDevice {
    fn recv(&self) -> io::Result<Option<Vec<u8>>> {
        let fd = self.file.as_raw_fd();
        loop {
            if self.stop.load(Ordering::SeqCst) {
                return Ok(None);
            }
            if sys::poll_readable(fd, POLL_MS)? {
                let mut buf = vec![0u8; MAX_PACKET];
                let n = (&self.file).read(&mut buf)?;
                buf.truncate(n);
                return Ok(Some(buf));
            }
        }
    }

    fn send(&self, packet: &[u8]) -> io::Result<()> {
        // One write per packet; the kernel takes it whole or not at all.
        let n = (&self.file).write(packet)?;
        if n != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("short write to {}", self.name),
            ));
        }
        Ok(())
    }

    fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    fn if_id(&self) -> u64 {
        self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::netconfig::{DnsMode, LinuxNetConfig, SystemRunner};
    use std::net::{Ipv4Addr, UdpSocket};
    use vpn_core::traits::{NetChange, NetConfig};

    /// Needs root or CAP_NET_ADMIN:
    /// `sudo -E cargo test -p ipsec-service -- --ignored linux_`
    #[test]
    #[ignore]
    fn linux_tun_roundtrip() {
        let dev = LinuxTunFactory.create().expect("create TUN (root?)");
        let net = LinuxNetConfig::with_dns(SystemRunner, DnsMode::Resolved);
        net.apply(&NetChange::AdapterAddress {
            if_id: dev.if_id(),
            addr: Ipv4Addr::new(10, 250, 0, 1),
            prefix: 30,
        })
        .expect("configure address");

        let s = UdpSocket::bind("10.250.0.1:0").unwrap();
        s.send_to(b"through-the-tun", "10.250.0.2:9").unwrap();
        let pkt = loop {
            let p = dev.recv().unwrap().expect("packet");
            // Skip anything that is not our IPv4/UDP datagram (e.g. IPv6 RS).
            if p.len() > 20 && p[0] >> 4 == 4 && p[9] == 17 {
                break p;
            }
        };
        assert_eq!(&pkt[16..20], &[10, 250, 0, 2]);
        assert!(pkt.ends_with(b"through-the-tun"));

        dev.shutdown();
        assert_eq!(dev.recv().unwrap(), None);
        let index = dev.if_id();
        drop(dev);
        // Non-persistent: the interface is gone once the fd is closed.
        assert!(sys::if_index("ipsec0").unwrap() != Some(index));
    }
}
