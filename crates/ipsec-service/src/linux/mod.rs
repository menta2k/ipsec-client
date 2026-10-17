//! Linux back-end (feature 002): the counterparts of `src/windows/`.
//!
//! `netconfig` and `systemd` only build commands and parse their output, so
//! they compile (and are unit-tested) on every OS. The modules that make
//! syscalls are Linux-only; `unsafe` is confined to `sys`.

// Off Linux only the unit tests use `group`, `netconfig` and `systemd`.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

pub mod group;
pub mod netconfig;
#[cfg(target_os = "linux")]
pub mod sys;
pub mod systemd;
#[cfg(target_os = "linux")]
pub mod tun;
