//! Tunnel interface over a kernel utun (004 research R1).
//!
//! The kernel removes the interface, with its addresses and routes, as soon
//! as the control socket closes, including when the service dies. Each packet
//! on the socket carries a 4-byte address-family header, which this module
//! adds and strips so the engine sees bare IPv4 packets as on other platforms.

use super::sys;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, info};
use vpn_core::traits::{TunDevice, TunFactory};

/// How long `recv` blocks before re-checking for `shutdown`.
const POLL_MS: i32 = 250;
const MAX_PACKET: usize = 65_535;
const AF_HEADER: usize = 4;

pub struct MacTunFactory;

impl TunFactory for MacTunFactory {
    fn create(&self) -> io::Result<Arc<dyn TunDevice>> {
        let (fd, name) = sys::utun_open()?;
        let index = sys::if_index(&name)
            .ok_or_else(|| io::Error::other(format!("{name} vanished right after creation")))?;
        info!(target: "tun", name = %name, index, "tunnel interface created");
        Ok(Arc::new(MacTunDevice {
            // Reads and writes on the control socket are plain read/write.
            file: File::from(fd),
            name,
            index,
            stop: AtomicBool::new(false),
        }))
    }

    fn remove_stale(&self) -> io::Result<()> {
        // utun interfaces die with their socket: a crashed run left none.
        debug!(target: "tun", "no stale utun possible");
        Ok(())
    }
}

pub struct MacTunDevice {
    file: File,
    name: String,
    index: u64,
    stop: AtomicBool,
}

/// The IPv4 payload of one utun read, or `None` for other families (IPv6
/// router solicitations and the like).
pub fn strip_af_header(frame: &[u8]) -> Option<&[u8]> {
    let (hdr, packet) = frame.split_at_checked(AF_HEADER)?;
    (u32::from_be_bytes(hdr.try_into().ok()?) == libc_af_inet()).then_some(packet)
}

/// One utun write for an IPv4 packet.
pub fn add_af_header(packet: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(AF_HEADER + packet.len());
    frame.extend_from_slice(&libc_af_inet().to_be_bytes());
    frame.extend_from_slice(packet);
    frame
}

/// `AF_INET`, which is 2 on every BSD including macOS.
const fn libc_af_inet() -> u32 {
    2
}

impl TunDevice for MacTunDevice {
    fn recv(&self) -> io::Result<Option<Vec<u8>>> {
        let fd = self.file.as_raw_fd();
        let mut buf = vec![0u8; AF_HEADER + MAX_PACKET];
        loop {
            if self.stop.load(Ordering::SeqCst) {
                return Ok(None);
            }
            if sys::poll_readable(fd, POLL_MS)? {
                let n = (&self.file).read(&mut buf)?;
                if let Some(p) = strip_af_header(&buf[..n]) {
                    return Ok(Some(p.to_vec()));
                }
            }
        }
    }

    fn send(&self, packet: &[u8]) -> io::Result<()> {
        // One write per packet; the kernel takes it whole or not at all.
        let frame = add_af_header(packet);
        let n = (&self.file).write(&frame)?;
        if n != frame.len() {
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

    #[test]
    fn af_header_round_trip_and_filtering() {
        let ip = [0x45u8, 0, 0, 20];
        let frame = add_af_header(&ip);
        assert_eq!(&frame[..4], &[0, 0, 0, 2]);
        assert_eq!(strip_af_header(&frame), Some(&ip[..]));
        // AF_INET6 (30 on macOS) and runts are dropped.
        assert_eq!(strip_af_header(&[0, 0, 0, 30, 0x60]), None);
        assert_eq!(strip_af_header(&[0, 0]), None);
    }

    /// Needs root: `sudo cargo test -p ipsec-service -- --ignored macos_`
    #[test]
    #[ignore]
    fn macos_utun_roundtrip() {
        use crate::macos::netconfig::MacNetConfig;
        use crate::macos::SysIfNames;
        use crate::unix_cmd::SystemRunner;
        use std::net::{Ipv4Addr, UdpSocket};
        use vpn_core::traits::{NetChange, NetConfig};

        let dev = MacTunFactory.create().expect("create utun (root?)");
        let net = MacNetConfig::new(SystemRunner, SysIfNames);
        net.apply(&NetChange::AdapterAddress {
            if_id: dev.if_id(),
            addr: Ipv4Addr::new(10, 250, 0, 1),
            prefix: 32,
        })
        .expect("configure address");
        net.apply(&NetChange::Route {
            if_id: dev.if_id(),
            dest: Ipv4Addr::new(10, 250, 0, 0),
            prefix: 30,
            next_hop: Ipv4Addr::UNSPECIFIED,
        })
        .expect("route");

        let s = UdpSocket::bind("10.250.0.1:0").unwrap();
        s.send_to(b"through-the-utun", "10.250.0.2:9").unwrap();
        let pkt = loop {
            let p = dev.recv().unwrap().expect("packet");
            if p.len() > 20 && p[0] >> 4 == 4 && p[9] == 17 {
                break p;
            }
        };
        assert_eq!(&pkt[16..20], &[10, 250, 0, 2]);
        assert!(pkt.ends_with(b"through-the-utun"));

        dev.shutdown();
        assert_eq!(dev.recv().unwrap(), None);
        let index = dev.if_id();
        drop(dev);
        // The interface is gone once the socket is closed.
        assert_eq!(sys::if_name(index), None);
    }
}
