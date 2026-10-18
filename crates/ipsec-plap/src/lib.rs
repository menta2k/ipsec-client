//! `ipsec-plap`: the Pre-Login Connect provider (feature 003).
//!
//! LogonUI loads this DLL to show "Network sign-in" entries for the VPN
//! profiles an administrator made available at sign-in. It is only an IPC
//! client of `ipsec-service`; the service owns the tunnel and enforces every
//! rule (003 research R4).
//!
//! * [`logic`] and [`ipc`] are portable and `forbid(unsafe_code)`; they hold
//!   all behaviour and are unit-tested on any OS.
//! * The COM layer (Windows only) is a thin shell over them; it never lets a
//!   panic reach LogonUI and never blocks its UI thread (research R2).
//! * `pipe_owner` (Windows only) is an OS binding: the service pipe's owner,
//!   checked before anything is sent to it.

pub mod ipc;
pub mod logic;
#[cfg(windows)]
mod pipe_owner;
