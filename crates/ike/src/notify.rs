//! Notify helpers: error detection, names, and user-facing messages (FR-018).

use crate::constants::{notify, PayloadType};
use crate::dh::DhGroup;
use crate::message::RawPayload;
use crate::payloads::NotifyPayload;

/// Notify types below 16384 are errors (RFC 7296 §3.10.1).
pub const ERROR_MAX: u16 = 16383;

/// The first error notify in a payload list, if any.
pub fn first_error(payloads: &[RawPayload]) -> Option<NotifyPayload> {
    payloads
        .iter()
        .filter(|p| p.payload_type == PayloadType::Notify as u8)
        .filter_map(|p| NotifyPayload::decode(&p.data).ok())
        .find(|n| n.notify_type <= ERROR_MAX)
}

/// Find a notify of the given type.
pub fn find(payloads: &[RawPayload], notify_type: u16) -> Option<NotifyPayload> {
    payloads
        .iter()
        .filter(|p| p.payload_type == PayloadType::Notify as u8)
        .filter_map(|p| NotifyPayload::decode(&p.data).ok())
        .find(|n| n.notify_type == notify_type)
}

/// Symbolic name of a notify type.
pub fn name(t: u16) -> &'static str {
    match t {
        notify::UNSUPPORTED_CRITICAL_PAYLOAD => "UNSUPPORTED_CRITICAL_PAYLOAD",
        notify::INVALID_IKE_SPI => "INVALID_IKE_SPI",
        notify::INVALID_MAJOR_VERSION => "INVALID_MAJOR_VERSION",
        notify::INVALID_SYNTAX => "INVALID_SYNTAX",
        notify::INVALID_MESSAGE_ID => "INVALID_MESSAGE_ID",
        notify::INVALID_SPI => "INVALID_SPI",
        notify::NO_PROPOSAL_CHOSEN => "NO_PROPOSAL_CHOSEN",
        notify::INVALID_KE_PAYLOAD => "INVALID_KE_PAYLOAD",
        notify::AUTHENTICATION_FAILED => "AUTHENTICATION_FAILED",
        notify::SINGLE_PAIR_REQUIRED => "SINGLE_PAIR_REQUIRED",
        notify::NO_ADDITIONAL_SAS => "NO_ADDITIONAL_SAS",
        notify::INTERNAL_ADDRESS_FAILURE => "INTERNAL_ADDRESS_FAILURE",
        notify::TS_UNACCEPTABLE => "TS_UNACCEPTABLE",
        notify::INVALID_SELECTORS => "INVALID_SELECTORS",
        notify::COOKIE => "COOKIE",
        _ => "UNKNOWN_ERROR",
    }
}

/// A sentence suitable for showing to the user.
pub fn user_message(t: u16) -> String {
    match t {
        notify::NO_PROPOSAL_CHOSEN => {
            "The gateway rejected all offered encryption proposals (NO_PROPOSAL_CHOSEN)".into()
        }
        notify::INVALID_KE_PAYLOAD => {
            "The gateway requires a different Diffie-Hellman group (INVALID_KE_PAYLOAD)".into()
        }
        notify::AUTHENTICATION_FAILED => {
            "Authentication failed: the gateway rejected the credentials (AUTHENTICATION_FAILED)"
                .into()
        }
        notify::TS_UNACCEPTABLE => {
            "The gateway rejected the requested traffic selectors (TS_UNACCEPTABLE)".into()
        }
        notify::INVALID_SYNTAX => {
            "The gateway reported a malformed message (INVALID_SYNTAX)".into()
        }
        notify::INTERNAL_ADDRESS_FAILURE => {
            "The gateway could not assign an internal address (INTERNAL_ADDRESS_FAILURE)".into()
        }
        notify::COOKIE => {
            "The gateway demands a COOKIE (DoS protection); this is not supported in this version"
                .into()
        }
        other => format!("The gateway returned error {} ({other})", name(other)),
    }
}

/// For INVALID_KE_PAYLOAD, the DH group the responder wants (2-byte data).
pub fn requested_dh_group(n: &NotifyPayload) -> Option<DhGroup> {
    if n.notify_type != notify::INVALID_KE_PAYLOAD || n.data.len() < 2 {
        return None;
    }
    DhGroup::from_transform_id(u16::from_be_bytes([n.data[0], n.data[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(n: &NotifyPayload) -> RawPayload {
        RawPayload {
            payload_type: PayloadType::Notify as u8,
            critical: false,
            data: n.encode(),
        }
    }

    #[test]
    fn finds_errors_and_ignores_status() {
        let status = NotifyPayload {
            protocol_id: 0,
            notify_type: notify::NAT_DETECTION_SOURCE_IP,
            spi: vec![],
            data: vec![1; 20],
        };
        let err = NotifyPayload {
            protocol_id: 0,
            notify_type: notify::NO_PROPOSAL_CHOSEN,
            spi: vec![],
            data: vec![],
        };
        assert!(first_error(&[raw(&status)]).is_none());
        assert_eq!(
            first_error(&[raw(&status), raw(&err)]).unwrap().notify_type,
            14
        );
        assert!(user_message(14).contains("NO_PROPOSAL_CHOSEN"));
    }

    #[test]
    fn invalid_ke_group() {
        let n = NotifyPayload {
            protocol_id: 0,
            notify_type: notify::INVALID_KE_PAYLOAD,
            spi: vec![],
            data: 31u16.to_be_bytes().to_vec(),
        };
        assert_eq!(requested_dh_group(&n), Some(DhGroup::Curve25519));
    }
}
