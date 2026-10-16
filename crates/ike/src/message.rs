//! IKEv2 message framing: the 28-byte IKE header and the generic payload chain
//! (RFC 7296 §3.1, §3.2).
//!
//! A message is the fixed header followed by a singly-linked chain of payloads,
//! each carrying the type of the *next* payload. This module parses/serialises
//! that structure as raw payload blobs; [`crate::payloads`] gives typed views of
//! the blob bodies.

use crate::constants::{ExchangeType, PayloadType, IKE_VERSION};

/// The 28-byte IKE header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IkeHeader {
    pub initiator_spi: [u8; 8],
    pub responder_spi: [u8; 8],
    pub next_payload: u8,
    pub version: u8,
    pub exchange_type: u8,
    pub flags: u8,
    pub message_id: u32,
    pub length: u32,
}

pub const HEADER_LEN: usize = 28;
pub const GENERIC_PAYLOAD_HEADER_LEN: usize = 4;

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    BadLength,
    BadVersion,
}

/// One payload as it appears on the wire, minus the 4-byte generic header.
/// `next_payload` is the type of the following payload (0 = end of chain).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawPayload {
    pub payload_type: u8,
    pub critical: bool,
    pub data: Vec<u8>,
}

/// A whole IKEv2 message: header fields plus the ordered payload chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub initiator_spi: [u8; 8],
    pub responder_spi: [u8; 8],
    pub exchange_type: u8,
    pub flags: u8,
    pub message_id: u32,
    pub payloads: Vec<RawPayload>,
}

impl Message {
    pub fn exchange(&self) -> Option<ExchangeType> {
        ExchangeType::from_u8(self.exchange_type)
    }

    /// Parse a complete IKEv2 message from `buf`.
    pub fn parse(buf: &[u8]) -> Result<Message, ParseError> {
        if buf.len() < HEADER_LEN {
            return Err(ParseError::Truncated);
        }
        let version = buf[17];
        // Major version is the high nibble; must be 2.
        if version >> 4 != 2 {
            return Err(ParseError::BadVersion);
        }
        let length = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]) as usize;
        if length < HEADER_LEN || length > buf.len() {
            return Err(ParseError::BadLength);
        }
        let mut hdr_init = [0u8; 8];
        let mut hdr_resp = [0u8; 8];
        hdr_init.copy_from_slice(&buf[0..8]);
        hdr_resp.copy_from_slice(&buf[8..16]);
        let first_next = buf[16];
        let exchange_type = buf[18];
        let flags = buf[19];
        let message_id = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);

        let payloads = parse_payload_chain(first_next, &buf[HEADER_LEN..length])?;

        Ok(Message {
            initiator_spi: hdr_init,
            responder_spi: hdr_resp,
            exchange_type,
            flags,
            message_id,
            payloads,
        })
    }

    /// Serialise the message, filling in `next_payload` links and `length`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let first_next = self
            .payloads
            .first()
            .map(|p| p.payload_type)
            .unwrap_or(PayloadType::None as u8);

        let mut body = Vec::new();
        write_payload_chain(&self.payloads, &mut body);

        let total = HEADER_LEN + body.len();
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&self.initiator_spi);
        out.extend_from_slice(&self.responder_spi);
        out.push(first_next);
        out.push(IKE_VERSION);
        out.push(self.exchange_type);
        out.push(self.flags);
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&(total as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// The header reconstructed from this message (with a computed length).
    pub fn header(&self) -> IkeHeader {
        let first_next = self
            .payloads
            .first()
            .map(|p| p.payload_type)
            .unwrap_or(PayloadType::None as u8);
        let mut body = Vec::new();
        write_payload_chain(&self.payloads, &mut body);
        IkeHeader {
            initiator_spi: self.initiator_spi,
            responder_spi: self.responder_spi,
            next_payload: first_next,
            version: IKE_VERSION,
            exchange_type: self.exchange_type,
            flags: self.flags,
            message_id: self.message_id,
            length: (HEADER_LEN + body.len()) as u32,
        }
    }

    /// Find the first payload of a given type.
    pub fn find(&self, t: PayloadType) -> Option<&RawPayload> {
        self.payloads.iter().find(|p| p.payload_type == t as u8)
    }
}

/// Parse a payload chain starting with payload type `first_next`.
pub fn parse_payload_chain(first_next: u8, mut buf: &[u8]) -> Result<Vec<RawPayload>, ParseError> {
    let mut payloads = Vec::new();
    let mut next = first_next;
    while next != PayloadType::None as u8 {
        if buf.len() < GENERIC_PAYLOAD_HEADER_LEN {
            return Err(ParseError::Truncated);
        }
        let this_type = next;
        let following = buf[0];
        let critical = buf[1] & 0x80 != 0;
        let plen = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if plen < GENERIC_PAYLOAD_HEADER_LEN || plen > buf.len() {
            return Err(ParseError::BadLength);
        }
        let data = buf[GENERIC_PAYLOAD_HEADER_LEN..plen].to_vec();
        payloads.push(RawPayload {
            payload_type: this_type,
            critical,
            data,
        });
        buf = &buf[plen..];
        // An SK (Encrypted) payload is always the last payload in a message; its
        // next-payload field names the first *encrypted* inner payload, not a
        // further cleartext one, so stop the cleartext chain here.
        if this_type == PayloadType::Sk as u8 {
            break;
        }
        next = following;
    }
    Ok(payloads)
}

/// Serialise a payload chain, linking each payload to the next.
pub fn write_payload_chain(payloads: &[RawPayload], out: &mut Vec<u8>) {
    for (i, p) in payloads.iter().enumerate() {
        let next = payloads
            .get(i + 1)
            .map(|n| n.payload_type)
            .unwrap_or(PayloadType::None as u8);
        let plen = (GENERIC_PAYLOAD_HEADER_LEN + p.data.len()) as u16;
        out.push(next);
        out.push(if p.critical { 0x80 } else { 0 });
        out.extend_from_slice(&plen.to_be_bytes());
        out.extend_from_slice(&p.data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let msg = Message {
            initiator_spi: [1, 2, 3, 4, 5, 6, 7, 8],
            responder_spi: [0; 8],
            exchange_type: ExchangeType::IkeSaInit as u8,
            flags: crate::constants::FLAG_INITIATOR,
            message_id: 0,
            payloads: vec![
                RawPayload {
                    payload_type: PayloadType::Nonce as u8,
                    critical: false,
                    data: vec![0xaa; 16],
                },
                RawPayload {
                    payload_type: PayloadType::VendorId as u8,
                    critical: false,
                    data: b"fortinet".to_vec(),
                },
            ],
        };
        let bytes = msg.to_bytes();
        assert_eq!(bytes.len(), 28 + (4 + 16) + (4 + 8));
        // header length field matches
        assert_eq!(
            u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]) as usize,
            bytes.len()
        );
        // first next-payload is Nonce (40)
        assert_eq!(bytes[16], PayloadType::Nonce as u8);
        let back = Message::parse(&bytes).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn rejects_truncated_and_bad_version() {
        assert_eq!(Message::parse(&[0u8; 10]), Err(ParseError::Truncated));
        let mut buf = vec![0u8; 28];
        buf[17] = 0x10; // major version 1
        buf[24..28].copy_from_slice(&28u32.to_be_bytes());
        assert_eq!(Message::parse(&buf), Err(ParseError::BadVersion));
    }

    #[test]
    fn chain_links_next_payload_fields() {
        let payloads = vec![
            RawPayload {
                payload_type: 33,
                critical: false,
                data: vec![1],
            },
            RawPayload {
                payload_type: 34,
                critical: false,
                data: vec![2, 3],
            },
            RawPayload {
                payload_type: 40,
                critical: false,
                data: vec![4],
            },
        ];
        let mut body = Vec::new();
        write_payload_chain(&payloads, &mut body);
        let parsed = parse_payload_chain(33, &body).unwrap();
        assert_eq!(parsed, payloads);
    }
}
