//! Versioned GUI <-> service IPC contract (contracts/ipc-protocol.md).
//!
//! Platform-neutral and free of `unsafe`: the GUI links only this crate.

#![forbid(unsafe_code)]

pub mod client;
pub mod framing;
pub mod messages;

pub use client::{ClientError, CommandClient, EventStream, Snapshot};
pub use messages::*;

/// CLSID of the Pre-Login Connect (PLAP) provider DLL. Fixed forever: the
/// installer, the recovery procedure and `ipsec-service plc disable-provider`
/// all name it (003 contracts/plap-registration.md).
pub const PLAP_CLSID: &str = "{6F1B0E52-3C4A-4D8E-9B61-2A7C5D0E8F13}";
