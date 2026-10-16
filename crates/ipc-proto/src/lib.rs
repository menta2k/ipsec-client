//! Versioned GUI <-> service IPC contract (contracts/ipc-protocol.md).
//!
//! Platform-neutral and free of `unsafe`: the GUI links only this crate.

#![forbid(unsafe_code)]

pub mod client;
pub mod framing;
pub mod messages;

pub use client::{ClientError, CommandClient, EventStream, Snapshot};
pub use messages::*;
