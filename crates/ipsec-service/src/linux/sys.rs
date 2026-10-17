//! The few raw syscalls the Linux back-end needs. All `unsafe` of the Linux
//! port lives here (002 plan, Constraints).

use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;

const IFNAMSIZ: usize = 16;
/// `_IOW('T', 202, int)` from `<linux/if_tun.h>`.
const TUNSETIFF: u64 = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
/// Fail with `EBUSY` instead of attaching to an existing device.
const IFF_TUN_EXCL: libc::c_short = 0x8000u16 as libc::c_short;

/// `struct ifreq` as used by `TUNSETIFF`: the name, then the flags inside the
/// 24-byte union (`struct ifreq` is 40 bytes on 64-bit Linux).
#[repr(C)]
struct IfReqFlags {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

/// Turn an open `/dev/net/tun` fd into a new layer-3 TUN interface `name`
/// (no packet-info header). Returns the kernel's name for it.
pub fn tun_set_iff(fd: RawFd, name: &str) -> io::Result<String> {
    if name.is_empty() || name.len() >= IFNAMSIZ || name.bytes().any(|b| b == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bad interface name",
        ));
    }
    let mut req = IfReqFlags {
        name: [0; IFNAMSIZ],
        flags: IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL,
        _pad: [0; 22],
    };
    for (d, s) in req.name.iter_mut().zip(name.bytes()) {
        *d = s as libc::c_char;
    }
    // SAFETY: `fd` is an open /dev/net/tun descriptor owned by the caller and
    // `req` is a properly sized, initialized `struct ifreq` that outlives the
    // call; TUNSETIFF only reads and writes within it.
    let rc = unsafe { libc::ioctl(fd, TUNSETIFF as _, &mut req as *mut IfReqFlags) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let len = req.name.iter().position(|&c| c == 0).unwrap_or(IFNAMSIZ);
    Ok(req.name[..len].iter().map(|&c| c as u8 as char).collect())
}

/// Wait up to `timeout_ms` for `fd` to become readable (or report an error /
/// hang-up, which the following read will surface). `EINTR` counts as "not
/// yet".
pub fn poll_readable(fd: RawFd, timeout_ms: i32) -> io::Result<bool> {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid, initialized pollfd for the duration of the call.
    let rc = unsafe { libc::poll(&mut p, 1, timeout_ms) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::Interrupted {
            Ok(false)
        } else {
            Err(e)
        };
    }
    Ok(rc > 0)
}

/// Kernel index of interface `name`, or `None` if it does not exist.
pub fn if_index(name: &str) -> io::Result<Option<u64>> {
    let c = CString::new(name).map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: `c` is a valid NUL-terminated string for the call's duration.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        let e = io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::ENODEV) | Some(libc::ENXIO) => Ok(None),
            _ => Err(e),
        };
    }
    Ok(Some(u64::from(idx)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifreq_layout_matches_the_kernel() {
        assert_eq!(std::mem::size_of::<IfReqFlags>(), 40);
        assert_eq!(std::mem::offset_of!(IfReqFlags, flags), IFNAMSIZ);
    }

    #[test]
    fn loopback_has_an_index_and_nonsense_does_not() {
        assert!(if_index("lo").unwrap().is_some());
        assert_eq!(if_index("no-such-if0").unwrap(), None);
    }

    #[test]
    fn rejects_bad_names_before_any_syscall() {
        assert!(tun_set_iff(-1, "").is_err());
        assert!(tun_set_iff(-1, "a-name-that-is-too-long").is_err());
    }
}
