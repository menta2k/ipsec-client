//! macOS back-end (feature 004): the counterparts of `src/linux/` and
//! `src/windows/`.
//!
//! `netconfig`, `group`, `launchd` and `syslog` only build commands and parse their
//! output, so they compile (and are unit-tested) on every OS. The modules that
//! make syscalls are macOS-only; `unsafe` is confined to `sys`.

// Off macOS only the unit tests use the portable modules.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub mod group;
pub mod launchd;
pub mod netconfig;
pub mod package;
#[cfg(target_os = "macos")]
pub mod socket;
#[cfg(target_os = "macos")]
pub mod sys;
pub mod syslog;
#[cfg(target_os = "macos")]
pub mod utun;

/// Interface names from the kernel.
#[cfg(target_os = "macos")]
pub struct SysIfNames;

#[cfg(target_os = "macos")]
impl netconfig::IfNames for SysIfNames {
    fn name(&self, index: u64) -> Option<String> {
        sys::if_name(index)
    }
    fn index(&self, name: &str) -> Option<u64> {
        sys::if_index(name)
    }
}
