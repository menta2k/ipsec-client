//! IKEv2 protocol core for the IPsec client.
//!
//! A self-contained port of the `ike-connect` prototype's protocol code, hardened
//! for product use (zeroized secrets, constant-time comparisons, anti-replay).
//! It is OS-agnostic and performs no I/O: callers feed it bytes and send what it
//! returns.
//!
//! * [`message`] - the IKE header and the generic payload chain.
//! * [`payloads`] - typed codecs for SA, KE, ID, AUTH, Notify, Delete, CP and TS.
//! * [`constants`] - IANA registries (exchanges, payloads, transforms, notifies).
//! * [`crypto`] - PRF, `prf+`, SKEYSEED, the seven IKE keys, PSK AUTH.
//! * [`dh`] - MODP-1536/2048 and Curve25519 key agreement.
//! * [`sk`] - the encrypted (SK) payload: AES-GCM-16 and AES-CBC + HMAC-SHA2.
//! * [`sa`] - the initiator handshake state ([`sa::Initiator`]).
//! * [`esp`] - ESP Child SA transforms with an anti-replay window.
//! * [`eap`] - EAP framing and EAP-MSCHAPv2 (RFC 2759 / RFC 3079).
//! * [`proposals`] - the default IKE/ESP proposals offered by the client.
//! * [`notify`] - human-readable names and messages for notify types.

#![forbid(unsafe_code)]

pub mod constants;
pub mod crypto;
pub mod dh;
pub mod eap;
pub mod esp;
pub mod message;
pub mod notify;
pub mod payloads;
pub mod proposals;
pub mod rng;
pub mod sa;
pub mod sk;

pub use message::{Message, RawPayload};

/// Constant-time byte-slice equality (lengths are not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}
