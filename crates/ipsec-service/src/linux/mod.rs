//! Linux back-end (feature 002): the counterparts of `src/windows/`.
//!
//! `netconfig` only builds commands and parses their output, so it compiles
//! (and is unit-tested) on every OS. The modules that make syscalls are
//! Linux-only; `unsafe` is confined to `sys`.

// TODO(T011/T016): the runner seam is wired into LinuxNetConfig and the
// Linux host in US1; until then nothing outside the tests uses it.
#![allow(dead_code)]

pub mod netconfig;
