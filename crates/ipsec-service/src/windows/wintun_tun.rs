//! Wintun implementation of the TUN traits (research R5). `wintun.dll` is
//! loaded from the executable's directory. Wintun adapters are software
//! devices tied to their handle, so an adapter disappears when the process
//! exits -- including on a crash.

use std::io;
use std::sync::Arc;
use tracing::info;
use vpn_core::traits::{TunDevice, TunFactory};

pub const ADAPTER_NAME: &str = "IpsecClient";
const TUNNEL_TYPE: &str = "IpsecClient";
/// Fixed adapter GUID so the same interface identity is reused.
const ADAPTER_GUID: u128 = 0x6f1d_2a8e_93b4_4c77_a1e2_5b0c_d7e4_19a3;
const RING_CAPACITY: u32 = 0x40_0000; // 4 MiB

pub struct WintunFactory {
    wintun: wintun::Wintun,
}

impl WintunFactory {
    pub fn load() -> io::Result<Self> {
        let dll = std::env::current_exe()?
            .parent()
            .map(|d| d.join("wintun.dll"))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no executable directory"))?;
        // SAFETY: loading the signed Wintun DLL shipped next to our executable;
        // its exports are only called through the `wintun` crate's bindings.
        let wintun = unsafe { wintun::load_from_path(&dll) }.map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("could not load {}: {e}", dll.display()),
            )
        })?;
        Ok(WintunFactory { wintun })
    }
}

impl TunFactory for WintunFactory {
    fn create(&self) -> io::Result<Arc<dyn TunDevice>> {
        let adapter = match wintun::Adapter::open(&self.wintun, ADAPTER_NAME) {
            Ok(a) => a,
            Err(_) => {
                wintun::Adapter::create(&self.wintun, ADAPTER_NAME, TUNNEL_TYPE, Some(ADAPTER_GUID))
                    .map_err(|e| io::Error::other(format!("create Wintun adapter: {e}")))?
            }
        };
        let session = Arc::new(
            adapter
                .start_session(RING_CAPACITY)
                .map_err(|e| io::Error::other(format!("start Wintun session: {e}")))?,
        );
        // SAFETY: NET_LUID_LH is a union whose `Value` arm covers all 64 bits.
        let luid = unsafe { adapter.get_luid().Value };
        info!(target: "tun", adapter = ADAPTER_NAME, "virtual adapter up");
        Ok(Arc::new(WintunDevice {
            session,
            _adapter: adapter,
            luid,
        }))
    }

    fn remove_stale(&self) -> io::Result<()> {
        // An adapter left by a crashed process is normally removed by Windows
        // with its handle. If one is still present, opening and dropping it
        // releases it; a fresh one is created on the next connect.
        if let Ok(a) = wintun::Adapter::open(&self.wintun, ADAPTER_NAME) {
            info!(target: "tun", "found a leftover adapter from a previous run");
            drop(a);
        }
        Ok(())
    }
}

pub struct WintunDevice {
    session: Arc<wintun::Session>,
    _adapter: Arc<wintun::Adapter>,
    luid: u64,
}

impl TunDevice for WintunDevice {
    fn recv(&self) -> io::Result<Option<Vec<u8>>> {
        match self.session.receive_blocking() {
            Ok(p) => Ok(Some(p.bytes().to_vec())),
            Err(wintun::Error::ShuttingDown) => Ok(None),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    fn send(&self, packet: &[u8]) -> io::Result<()> {
        let len = u16::try_from(packet.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet too large"))?;
        let mut p = self
            .session
            .allocate_send_packet(len)
            .map_err(|e| io::Error::other(e.to_string()))?;
        p.bytes_mut().copy_from_slice(packet);
        self.session.send_packet(p);
        Ok(())
    }

    fn shutdown(&self) {
        let _ = self.session.shutdown();
    }

    fn if_id(&self) -> u64 {
        self.luid
    }
}
