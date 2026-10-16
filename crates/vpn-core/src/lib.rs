//! OS-agnostic VPN engine for the IPsec client.
//!
//! * [`session`] - IKEv2 establishment (PSK / EAP-MSCHAPv2, NAT-T, retransmit).
//! * [`datapath`] - TUN <-> ESP relay, keepalive, DPD, counters.
//! * [`manager`] - the single-tunnel state machine, network journal, reconnect.
//! * [`store`] / [`profile`] - persisted profiles with protected secrets.
//! * [`routes`] - traffic-selector to route planning.
//! * [`logbuf`] / [`events`] - log ring and event fan-out for the GUI.
//! * [`traits`] - the platform abstractions; [`mock`] - their test doubles.

#![forbid(unsafe_code)]

pub mod datapath;
pub mod events;
pub mod logbuf;
pub mod manager;
pub mod mock;
pub mod profile;
pub mod routes;
pub mod session;
pub mod store;
pub mod traits;

pub use events::EventBus;
pub use logbuf::LogBuffer;
pub use manager::{ConnectionManager, Deps, EngineConfig, RejectError};
pub use store::ProfileStore;
