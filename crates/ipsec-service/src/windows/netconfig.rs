//! IP Helper implementation of `NetConfig` (research R6): adapter address,
//! routes, DNS (SetInterfaceDnsSettings with a netsh fallback), and the
//! interface metric/MTU tuned when the address is applied.

use super::wide;
use std::io;
use std::net::Ipv4Addr;
use tracing::{debug, warn};
use vpn_core::traits::{NetChange, NetConfig};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR, WIN32_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};

/// Tunnel MTU: leaves room for IPv4 + UDP + ESP (GCM/CBC) overhead on 1500.
const TUNNEL_MTU: u32 = 1400;
const MIB_IPPROTO_NETMGMT: i32 = 3;
const IP_DAD_STATE_PREFERRED: i32 = 4;

pub struct IpHelperNetConfig;

fn luid(v: u64) -> NET_LUID_LH {
    NET_LUID_LH { Value: v }
}

fn sockaddr_v4(ip: Ipv4Addr) -> SOCKADDR_INET {
    // SAFETY: SOCKADDR_INET is plain old data; all-zero is a valid value.
    let mut sa: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    sa.Ipv4.sin_family = AF_INET;
    sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
    sa
}

fn check(rc: WIN32_ERROR, what: &str) -> io::Result<()> {
    if rc == NO_ERROR {
        Ok(())
    } else {
        Err(io::Error::new(
            io::Error::from_raw_os_error(rc as i32).kind(),
            format!("{what}: {}", io::Error::from_raw_os_error(rc as i32)),
        ))
    }
}

fn address_row(if_id: u64, addr: Ipv4Addr, prefix: u8) -> MIB_UNICASTIPADDRESS_ROW {
    // SAFETY: zeroed POD, then initialized by the documented initializer.
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = luid(if_id);
    row.Address = sockaddr_v4(addr);
    row.OnLinkPrefixLength = prefix;
    row.DadState = IP_DAD_STATE_PREFERRED as _;
    row
}

fn route_row(if_id: u64, dest: Ipv4Addr, prefix: u8, next_hop: Ipv4Addr) -> MIB_IPFORWARD_ROW2 {
    // SAFETY: zeroed POD, then initialized by the documented initializer.
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid(if_id);
    row.DestinationPrefix.Prefix = sockaddr_v4(dest);
    row.DestinationPrefix.PrefixLength = prefix;
    row.NextHop = sockaddr_v4(next_hop);
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT as _;
    row
}

/// Low interface metric (so the tunnel DNS is preferred) and a safe MTU.
fn tune_interface(if_id: u64) -> io::Result<()> {
    // SAFETY: zeroed POD initialized by InitializeIpInterfaceEntry, then
    // filled by GetIpInterfaceEntry for (family, luid).
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = AF_INET;
    row.InterfaceLuid = luid(if_id);
    check(
        unsafe { GetIpInterfaceEntry(&mut row) },
        "GetIpInterfaceEntry",
    )?;
    row.UseAutomaticMetric = false;
    row.Metric = 1;
    row.NlMtu = TUNNEL_MTU;
    row.SitePrefixLength = 0; // must be 0 for IPv4 or SetIpInterfaceEntry fails
                              // SAFETY: row is a fully initialized interface row.
    check(
        unsafe { SetIpInterfaceEntry(&mut row) },
        "SetIpInterfaceEntry",
    )
}

fn set_dns(if_id: u64, servers: &[Ipv4Addr]) -> io::Result<()> {
    let list = servers
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let mut guid: GUID = GUID {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    };
    let l = luid(if_id);
    // SAFETY: valid pointers to locals.
    check(
        unsafe { ConvertInterfaceLuidToGuid(&l, &mut guid) },
        "ConvertInterfaceLuidToGuid",
    )?;
    let mut ns = wide(&list);
    // SAFETY: zeroed POD; NameServer points at `ns`, alive for the call.
    let mut settings: DNS_INTERFACE_SETTINGS = unsafe { std::mem::zeroed() };
    settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
    settings.Flags = DNS_SETTING_NAMESERVER as u64;
    settings.NameServer = ns.as_mut_ptr();
    let rc = unsafe { SetInterfaceDnsSettings(guid, &settings) };
    if rc == NO_ERROR {
        return Ok(());
    }
    // Pre-2004 Windows: fall back to netsh by interface alias.
    warn!(target: "netconfig", rc, "SetInterfaceDnsSettings failed; falling back to netsh");
    netsh_dns(if_id, servers)
}

fn alias(if_id: u64) -> io::Result<String> {
    let l = luid(if_id);
    let mut buf = [0u16; 257];
    // SAFETY: buffer length passed matches the buffer.
    check(
        unsafe { ConvertInterfaceLuidToAlias(&l, buf.as_mut_ptr(), buf.len()) },
        "ConvertInterfaceLuidToAlias",
    )?;
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Ok(String::from_utf16_lossy(&buf[..n]))
}

fn netsh_dns(if_id: u64, servers: &[Ipv4Addr]) -> io::Result<()> {
    let name = format!("name={}", alias(if_id)?);
    let mut cmds: Vec<Vec<String>> = Vec::new();
    match servers.first() {
        None => cmds.push(vec![
            "interface".into(),
            "ipv4".into(),
            "set".into(),
            "dnsservers".into(),
            name.clone(),
            "source=static".into(),
            "address=none".into(),
        ]),
        Some(first) => {
            cmds.push(vec![
                "interface".into(),
                "ipv4".into(),
                "set".into(),
                "dnsservers".into(),
                name.clone(),
                "source=static".into(),
                format!("address={first}"),
                "register=none".into(),
                "validate=no".into(),
            ]);
            for (i, s) in servers.iter().enumerate().skip(1) {
                cmds.push(vec![
                    "interface".into(),
                    "ipv4".into(),
                    "add".into(),
                    "dnsservers".into(),
                    name.clone(),
                    format!("address={s}"),
                    format!("index={}", i + 1),
                    "validate=no".into(),
                ]);
            }
        }
    }
    for args in cmds {
        let st = std::process::Command::new("netsh").args(&args).status()?;
        if !st.success() {
            return Err(io::Error::other("netsh failed to set DNS servers"));
        }
    }
    Ok(())
}

impl NetConfig for IpHelperNetConfig {
    fn apply(&self, change: &NetChange) -> io::Result<()> {
        debug!(target: "netconfig", ?change, "apply");
        match change {
            NetChange::AdapterAddress {
                if_id,
                addr,
                prefix,
            } => {
                if let Err(e) = tune_interface(*if_id) {
                    warn!(target: "netconfig", error = %e, "could not tune interface metric/MTU");
                }
                let row = address_row(*if_id, *addr, *prefix);
                // SAFETY: fully initialized row.
                let rc = unsafe { CreateUnicastIpAddressEntry(&row) };
                if rc == ERROR_OBJECT_ALREADY_EXISTS {
                    Ok(())
                } else {
                    check(rc, "CreateUnicastIpAddressEntry")
                }
            }
            NetChange::Route {
                if_id,
                dest,
                prefix,
                next_hop,
            } => {
                let row = route_row(*if_id, *dest, *prefix, *next_hop);
                // SAFETY: fully initialized row.
                let rc = unsafe { CreateIpForwardEntry2(&row) };
                if rc == ERROR_OBJECT_ALREADY_EXISTS {
                    Ok(())
                } else {
                    check(rc, "CreateIpForwardEntry2")
                }
            }
            NetChange::Dns { if_id, servers } => set_dns(*if_id, servers),
            NetChange::ResolvConf { .. } => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "resolv.conf changes are Linux-only",
            )),
        }
    }

    fn revert(&self, change: &NetChange) -> io::Result<()> {
        debug!(target: "netconfig", ?change, "revert");
        let rc = match change {
            NetChange::AdapterAddress {
                if_id,
                addr,
                prefix,
            } => {
                let row = address_row(*if_id, *addr, *prefix);
                // SAFETY: fully initialized row.
                unsafe { DeleteUnicastIpAddressEntry(&row) }
            }
            NetChange::Route {
                if_id,
                dest,
                prefix,
                next_hop,
            } => {
                let row = route_row(*if_id, *dest, *prefix, *next_hop);
                // SAFETY: fully initialized row.
                unsafe { DeleteIpForwardEntry2(&row) }
            }
            NetChange::Dns { if_id, .. } => {
                return match set_dns(*if_id, &[]) {
                    // The adapter may already be gone, which removes its DNS too.
                    Err(e) if e.raw_os_error().is_some() => Ok(()),
                    r => r,
                };
            }
            // Never produced on Windows; nothing to undo.
            NetChange::ResolvConf { .. } => return Ok(()),
        };
        // Already gone (e.g. adapter removed) counts as reverted.
        if rc == ERROR_NOT_FOUND || rc == windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND {
            return Ok(());
        }
        check(rc, "revert")
    }

    fn best_route(&self, dest: Ipv4Addr) -> io::Result<(u64, Ipv4Addr)> {
        let d = sockaddr_v4(dest);
        // SAFETY: zeroed POD out-params filled by GetBestRoute2.
        let mut route: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        let mut src: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            GetBestRoute2(
                std::ptr::null(),
                0,
                std::ptr::null(),
                &d,
                0,
                &mut route,
                &mut src,
            )
        };
        check(rc, "GetBestRoute2")?;
        // SAFETY: reading the IPv4 arm of unions GetBestRoute2 filled for AF_INET.
        let (if_id, nh) = unsafe {
            (
                route.InterfaceLuid.Value,
                route.NextHop.Ipv4.sin_addr.S_un.S_addr,
            )
        };
        Ok((if_id, Ipv4Addr::from(nh.to_ne_bytes())))
    }
}
