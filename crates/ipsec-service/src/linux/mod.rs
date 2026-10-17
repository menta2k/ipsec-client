//! Linux back-end (feature 002): the counterparts of `src/windows/`.
//!
//! `netconfig` only builds commands and parses their output, so it compiles
//! (and is unit-tested) on every OS. The modules that make syscalls are
//! Linux-only; `unsafe` is confined to `sys`.

// Off Linux only the unit tests use `netconfig`.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

pub mod netconfig;
#[cfg(target_os = "linux")]
pub mod sys;
#[cfg(target_os = "linux")]
pub mod tun;
