//! The few raw syscalls the macOS back-end needs. All `unsafe` of the macOS
//! port lives here (004 plan, Constraints).

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Kernel control that hands out utun interfaces (004 research R1).
const UTUN_CONTROL: &CStr = c"com.apple.net.utun_control";

/// Open a new utun interface; the kernel picks the unit. Returns the control
/// socket (close it and the interface disappears) and the interface name.
pub fn utun_open() -> io::Result<(OwnedFd, String)> {
    // SAFETY: plain socket(2) call; the result is checked before use.
    let raw = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a freshly created descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    set_cloexec(fd.as_raw_fd())?;

    // SAFETY: `ctl_info` is plain data; all-zero is a valid value.
    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    for (d, s) in info.ctl_name.iter_mut().zip(UTUN_CONTROL.to_bytes()) {
        *d = *s as libc::c_char;
    }
    // SAFETY: `fd` is open and `info` is a properly sized, initialized
    // `struct ctl_info` that outlives the call; CTLIOCGINFO fills `ctl_id`.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info) } < 0 {
        return Err(io::Error::last_os_error());
    }

    let addr = libc::sockaddr_ctl {
        sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as libc::c_uchar,
        sc_family: libc::AF_SYSTEM as libc::c_uchar,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: info.ctl_id,
        // 0: the kernel assigns the next free utunN.
        sc_unit: 0,
        sc_reserved: [0; 5],
    };
    // SAFETY: `addr` is a valid `sockaddr_ctl` of the length passed.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
    let mut len = name.len() as libc::socklen_t;
    // SAFETY: `name` has room for IFNAMSIZ bytes and `len` says so.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            name.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fd, c_name(&name)))
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor we own; F_SETFD takes an int flag.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn c_name(buf: &[libc::c_char]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    buf[..len].iter().map(|&c| c as u8 as char).collect()
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
pub fn if_index(name: &str) -> Option<u64> {
    let c = CString::new(name).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string for the call's duration.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (idx != 0).then_some(u64::from(idx))
}

/// Name of the interface with kernel index `index`, or `None`.
pub fn if_name(index: u64) -> Option<String> {
    let index = libc::c_uint::try_from(index).ok()?;
    let mut buf = [0 as libc::c_char; libc::IFNAMSIZ];
    // SAFETY: `buf` has the IFNAMSIZ bytes if_indextoname may write.
    let p = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    (!p.is_null()).then(|| c_name(&buf))
}

/// The connecting process of a Unix-socket connection: `(uid, gid, pid)`.
pub fn peer_cred(fd: RawFd) -> io::Result<(u32, u32, i32)> {
    // SAFETY: `xucred` is plain data; all-zero is a valid value.
    let mut cred: libc::xucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
    // SAFETY: `cred` is a properly sized `struct xucred` and `len` says so.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERCRED,
            &mut cred as *mut libc::xucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    if cred.cr_version != libc::XUCRED_VERSION {
        return Err(io::Error::other("unexpected xucred version"));
    }
    let gid = if cred.cr_ngroups > 0 {
        cred.cr_groups[0]
    } else {
        u32::MAX
    };

    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: `pid` is a `pid_t` and `len` is its size.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            &mut pid as *mut libc::pid_t as *mut libc::c_void,
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((cred.cr_uid, gid, pid))
}

/// True if this process runs as root.
pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Start sending to the system log as `ipsec-service` (004 research R8).
pub fn syslog_open() {
    // SAFETY: the identifier is a 'static C string, as openlog requires (it
    // keeps the pointer).
    unsafe { libc::openlog(c"ipsec-service".as_ptr(), libc::LOG_PID, libc::LOG_DAEMON) };
}

/// One message to the system log. Interior NULs are replaced.
pub fn syslog_write(priority: libc::c_int, message: &str) {
    let msg = CString::new(message.replace('\0', " ")).unwrap_or_default();
    // SAFETY: a constant "%s" format with exactly one valid C string argument,
    // so the message itself is never interpreted as a format.
    unsafe { libc::syslog(priority, c"%s".as_ptr(), msg.as_ptr()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_has_an_index_and_a_name() {
        let i = if_index("lo0").expect("lo0");
        assert_eq!(if_name(i).as_deref(), Some("lo0"));
        assert_eq!(if_index("no-such-if0"), None);
        assert_eq!(if_name(u64::from(u32::MAX)), None);
    }

    #[test]
    fn peer_cred_reports_this_process() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let (uid, _gid, pid) = peer_cred(a.as_raw_fd()).unwrap();
        // SAFETY: geteuid has no preconditions.
        assert_eq!(uid, unsafe { libc::geteuid() });
        assert_eq!(pid, std::process::id() as i32);
    }
}
